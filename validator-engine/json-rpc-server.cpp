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
#include "smc-envelope/GenericAccount.h"
#include "smc-envelope/SmartContract.h"
#include "tos/lite-tl.hpp"
#include "vm/cellops.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"
#include "vm/boc.h"
#include "vm/cells/CellString.h"
#include "vm/cp0.h"
#include "vm/vm.h"
#include "td/utils/crypto.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/base64.h"
#include <limits>

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
  // Arm periodic cache cleanup if caching is enabled
  if (opts_.cache_ttl > 0) {
    alarm_timestamp() = td::Timestamp::in(10.0);
  }
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

  // API key authentication (after CORS preflight and healthcheck, before all other routes)
  if (!check_api_key(request, promise)) {
    return;  // 401 already sent
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
    else if (path == "/getConsensusBlock")      rest_method = "getConsensusBlock";
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
    else if (path == "/getShards")              rest_method = "shards";
    else if (path == "/getBlockHeader")         rest_method = "getBlockHeader";
    else if (path == "/getBlockTransactions")   rest_method = "getBlockTransactions";
    else if (path == "/getExtendedAddressInformation") rest_method = "getExtendedAddressInformation";
    else if (path == "/estimateFee")            rest_method = "estimateFee";
    else if (path == "/tryLocateTx")            rest_method = "tryLocateTx";
    else if (path == "/tryLocateResultTx")      rest_method = "tryLocateResultTx";
    else if (path == "/tryLocateSourceTx")      rest_method = "tryLocateSourceTx";
    else if (path == "/getMasterchainBlockSignatures") rest_method = "getMasterchainBlockSignatures";
    else if (path == "/getShardBlockProof")     rest_method = "getShardBlockProof";
    else if (path == "/getLibraries")           rest_method = "getLibraries";
    else if (path == "/getTokenData")           rest_method = "getTokenData";
    else if (path == "/detectHash")             rest_method = "detectHash";
    else if (path == "/getOutMsgQueueSize")     rest_method = "getOutMsgQueueSize";
    else if (path == "/getConfigAll")           rest_method = "getConfigAll";
    else if (path == "/getTransactionsStd")     rest_method = "getTransactionsStd";
    else if (path == "/getBlockTransactionsExt") rest_method = "getBlockTransactionsExt";

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
      cached_dispatch_method(std::move(rest_method), json_val.get_object(),
                             "null", std::move(promise));
      return;
    }

    // Unknown GET path
    promise.set_value(make_text_response(404, "Not Found",
                                         "Unknown endpoint",
                                         opts_.cors_origin));
    return;
  }

  // Only POST is allowed beyond this point
  if (method != "POST") {
    promise.set_value(make_text_response(405, "Method Not Allowed",
                                         "Only POST, GET, and OPTIONS are supported",
                                         opts_.cors_origin));
    return;
  }

  // POST REST-style endpoints: /runGetMethod, /sendBoc, etc.
  // These use the POST body as params (same as JSON-RPC but without the envelope).
  // Check if the URL path matches a known method name — if so, treat the POST body
  // as the params object directly, without requiring jsonrpc/method/id envelope.
  {
    auto post_path = url;
    auto qpos = post_path.find('?');
    if (qpos != std::string::npos) post_path = post_path.substr(0, qpos);
    while (!post_path.empty() && post_path.back() == '/') post_path.pop_back();

    // Only match specific REST POST paths (not /jsonRPC which uses the standard envelope)
    // POST REST paths — write methods + methods with complex body params.
    // These accept POST body as the params JSON (no jsonrpc envelope).
    // GET-accessible methods are handled above; this covers the remaining 6.
    static const std::set<std::string> post_rest_paths = {
        "/runGetMethod", "/runGetMethodStd",
        "/sendBoc", "/sendBocReturnHash", "/sendBocReturnHashNoError",
        "/sendQuery", "/estimateFee"
    };
    if (post_rest_paths.count(post_path)) {
      std::string rest_method = post_path.substr(1);  // strip leading /
      // Read body and dispatch as REST (body = params JSON object)
      class PostRestWaiter : public http::HttpPayload::Callback {
       public:
        PostRestWaiter(td::actor::ActorId<JsonRpcServer> server, PayloadPtr payload,
                       std::string method, td::Promise<HttpReturn> promise)
            : server_(server), payload_(std::move(payload)),
              method_(std::move(method)), promise_(std::move(promise)) {}
        void run(size_t) override {}
        void completed() override {
          auto body = payload_->get_slice(1 << 20);
          td::actor::send_closure(server_, &JsonRpcServer::process_rest_post_body,
                                  std::move(body), std::move(method_), std::move(promise_));
        }
       private:
        td::actor::ActorId<JsonRpcServer> server_;
        PayloadPtr payload_;
        std::string method_;
        td::Promise<HttpReturn> promise_;
      };
      if (payload->parse_completed()) {
        auto body = payload->get_slice(1 << 20);
        process_rest_post_body(std::move(body), std::move(rest_method), std::move(promise));
      } else {
        payload->add_callback(std::make_unique<PostRestWaiter>(
            actor_id(this), payload, std::move(rest_method), std::move(promise)));
      }
      return;
    }
  }

  // Accept POST on /jsonRPC (canonical) and any other path (backward compat)

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
        if (fired_) {
          return;
        }
        fired_ = true;
        // Do NOT read payload here (mutex deadlock). Defer to actor scheduler.
        td::actor::send_closure(server_, &JsonRpcServer::on_body_ready,
                                payload_, std::move(promise_));
      }
     private:
      td::actor::ActorId<JsonRpcServer> server_;
      PayloadPtr payload_;
      td::Promise<HttpReturn> promise_;
      bool fired_ = false;
    };
    payload->add_callback(std::make_unique<BodyWaiter>(
        actor_id(this), payload, std::move(promise)));
  }
}

void JsonRpcServer::on_body_ready(PayloadPtr payload, td::Promise<HttpReturn> promise) {
  if (!payload) {
    promise.set_value(make_json_error(-32603, "Internal error: missing request payload", "null",
                                      opts_.cors_origin));
    return;
  }
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

  cached_dispatch_method(std::move(method), params_val.get_object(),
                         std::move(req_id), std::move(promise));
}

// ─── POST REST body processing (body = params JSON, no jsonrpc envelope) ──

void JsonRpcServer::process_rest_post_body(td::BufferSlice body, std::string method,
                                           td::Promise<HttpReturn> promise) {
  if (body.empty()) {
    // Empty body → empty params
    td::JsonObject empty_obj;
    cached_dispatch_method(std::move(method), empty_obj, "null", std::move(promise));
    return;
  }
  auto json_r = td::json_decode(body.as_slice());
  if (json_r.is_error()) {
    promise.set_value(make_json_error(-32700, "Parse error: invalid JSON body", "null",
                                      opts_.cors_origin));
    return;
  }
  auto json = json_r.move_as_ok();
  if (json.type() != td::JsonValue::Type::Object) {
    promise.set_value(make_json_error(-32602, "Body must be a JSON object", "null",
                                      opts_.cors_origin));
    return;
  }
  cached_dispatch_method(std::move(method), json.get_object(), "null", std::move(promise));
}

// ─── Method dispatch ──────────────────────────────────────────────────────

void JsonRpcServer::dispatch_method(std::string method, td::JsonObject &params,
                                    std::string req_id, td::Promise<HttpReturn> promise) {
  // Write-method gate: reject send-family methods in readonly mode
  if (opts_.readonly &&
      (method == "sendBoc" || method == "sendBocReturnHash" ||
       method == "sendBocReturnHashNoError" || method == "sendQuery")) {
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
  } else if (method == "getConsensusBlock") {
    handle_getConsensusBlock(params, std::move(req_id), std::move(promise));
  } else if (method == "lookupBlock") {
    handle_lookupBlock(params, std::move(req_id), std::move(promise));
  } else if (method == "shards" || method == "getShards") {
    handle_shards(params, std::move(req_id), std::move(promise));
  } else if (method == "getBlockHeader") {
    handle_getBlockHeader(params, std::move(req_id), std::move(promise));
  } else if (method == "getBlockTransactions") {
    handle_getBlockTransactions(params, std::move(req_id), std::move(promise));
  } else if (method == "getTransactions") {
    handle_getTransactions(params, std::move(req_id), std::move(promise));
  } else if (method == "getBlockTransactionsExt") {
    handle_getBlockTransactionsExt(params, std::move(req_id), std::move(promise));
  // Transaction lookup APIs
  } else if (method == "tryLocateTx") {
    handle_tryLocateTx(params, std::move(req_id), std::move(promise));
  } else if (method == "tryLocateResultTx") {
    handle_tryLocateResultTx(params, std::move(req_id), std::move(promise));
  } else if (method == "tryLocateSourceTx") {
    handle_tryLocateSourceTx(params, std::move(req_id), std::move(promise));
  // Block proof / signature APIs
  } else if (method == "getMasterchainBlockSignatures") {
    handle_getMasterchainBlockSignatures(params, std::move(req_id), std::move(promise));
  } else if (method == "getShardBlockProof") {
    handle_getShardBlockProof(params, std::move(req_id), std::move(promise));
  // Send family
  } else if (method == "sendBocReturnHash") {
    handle_sendBocReturnHash(params, std::move(req_id), std::move(promise));
  } else if (method == "sendQuery") {
    handle_sendQuery(params, std::move(req_id), std::move(promise));
  } else if (method == "estimateFee") {
    handle_estimateFee(params, std::move(req_id), std::move(promise));
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
  // Library & token data APIs
  } else if (method == "getLibraries") {
    handle_getLibraries(params, std::move(req_id), std::move(promise));
  } else if (method == "getTokenData") {
    handle_getTokenData(params, std::move(req_id), std::move(promise));
  // New APIs (parity with ton-http-api-cpp)
  } else if (method == "detectHash") {
    handle_detectHash(params, std::move(req_id), std::move(promise));
  } else if (method == "getOutMsgQueueSize") {
    handle_getOutMsgQueueSize(params, std::move(req_id), std::move(promise));
  } else if (method == "getConfigAll") {
    handle_getConfigAll(params, std::move(req_id), std::move(promise));
  } else if (method == "getTransactionsStd") {
    handle_getTransactionsStd(params, std::move(req_id), std::move(promise));
  } else if (method == "runGetMethodStd") {
    handle_runGetMethodStd(params, std::move(req_id), std::move(promise));
  } else if (method == "sendBocReturnHashNoError") {
    handle_sendBocReturnHashNoError(params, std::move(req_id), std::move(promise));
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
    // Try 'param' as alias
    config_id_r = params.get_required_int_field("param");
  }
  if (config_id_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'config_id' or 'param' parameter", req_id));
    return;
  }
  int config_id = config_id_r.ok();

  // Optional seqno: query config at a specific MC block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  // Step 2 lambda: query config at a resolved block
  auto do_query_config = [config_id, req_id = std::move(req_id),
                          self_id = actor_id(this), promise = std::move(promise)](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id) mutable {
        std::vector<td::int32> param_list = {config_id};
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getConfigParams>(
                0x10000, std::move(block_id), std::move(param_list)),
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
  };  // end of do_query_config

  // Step 1: resolve block
  if (has_seqno) {
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0), true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    send_liteserver_query(std::move(lookup_query),
        [do_query_config = std::move(do_query_config)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) return;
          do_query_config(std::move(lb_r.move_as_ok()->id_));
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_query_config = std::move(do_query_config)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) return;
          do_query_config(std::move(mc_r.move_as_ok()->last_));
        });
  }
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
  td::Ref<vm::Cell> data_cell;
  td::Ref<vm::Cell> extra_currencies_cell;
  td::Ref<vm::Cell> state_cell;
  tos::UnixTime storage_last_paid{0};
  block::StorageUsed storage_used;

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
          block::gen::StorageInfo::Record storage_info;
          if (tlb::csr_unpack(account.storage_stat, storage_info)) {
            res.storage_last_paid = storage_info.last_paid;
            block::gen::StorageUsed::Record storage_used;
            if (tlb::csr_unpack(storage_info.used, storage_used)) {
              unsigned long long u = 0;
              u |= res.storage_used.cells = block::tlb::t_VarUInteger_7.as_uint(*storage_used.cells);
              u |= res.storage_used.bits = block::tlb::t_VarUInteger_7.as_uint(*storage_used.bits);
              if (u == std::numeric_limits<td::uint64>::max()) {
                return td::Status::Error("Failed to unpack StorageStat");
              }
            }
          }

          block::gen::AccountStorage::Record storage;
          if (tlb::csr_unpack(account.storage, storage)) {
            auto balance_cs = storage.balance.write();
            auto coins = block::tlb::t_Tomis.as_integer_skip(balance_cs);
            if (coins.not_null()) res.balance = coins->to_long();
            res.extra_currencies_cell = storage.balance->prefetch_ref();

            auto tag = block::gen::t_AccountState.get_tag(*storage.state);
            if (tag == block::gen::AccountState::account_active) {
              res.state_str = "active";
              block::gen::AccountState::Record_account_active active;
              if (tlb::csr_unpack(storage.state, active)) {
                res.state_cell = vm::CellBuilder().append_cellslice(active.x).finalize();
                block::gen::StateInit::Record si;
                if (tlb::csr_unpack(active.x, si)) {
                  si.code->prefetch_maybe_ref(res.code_cell);
                  si.data->prefetch_maybe_ref(res.data_cell);
                  if (res.code_cell.not_null()) {
                    auto boc = vm::std_boc_serialize(res.code_cell);
                    if (boc.is_ok()) res.code_b64 = td::base64_encode(boc.ok().as_slice());
                  }
                  if (res.data_cell.not_null()) {
                    auto boc = vm::std_boc_serialize(res.data_cell);
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

static td::Result<td::Ref<vm::Cell>> parse_optional_boc_field(td::JsonObject& params, const char* name) {
  auto value_r = params.get_optional_string_field(td::Slice{name});
  if (value_r.is_error() || value_r.ok().empty()) {
    return td::Ref<vm::Cell>();
  }
  auto decoded_r = td::base64_decode(value_r.ok());
  if (decoded_r.is_error()) {
    return td::Status::Error(PSTRING() << "Invalid base64 in '" << name << "'");
  }
  auto cell_r = vm::std_boc_deserialize(td::Slice(decoded_r.ok()));
  if (cell_r.is_error()) {
    return td::Status::Error(PSTRING() << "Invalid BOC in '" << name << "'");
  }
  return cell_r.move_as_ok();
}

static td::RefInt256 estimate_compute_threshold(const block::GasLimitsPrices& cfg) {
  auto gas_price256 = td::RefInt256{true, cfg.gas_price};
  if (cfg.gas_limit > cfg.flat_gas_limit) {
    return td::rshift(gas_price256 * (cfg.gas_limit - cfg.flat_gas_limit), 16, 1) +
           td::make_refint(cfg.flat_gas_price);
  }
  return td::make_refint(cfg.flat_gas_price);
}

static td::uint64 estimate_gas_bought_for(td::RefInt256 nanotomis, td::RefInt256 max_gas_threshold,
                                          const block::GasLimitsPrices& cfg) {
  if (nanotomis.is_null() || sgn(nanotomis) < 0) {
    return 0;
  }
  if (nanotomis >= max_gas_threshold) {
    return cfg.gas_limit;
  }
  if (nanotomis < cfg.flat_gas_price) {
    return 0;
  }
  auto gas_price256 = td::RefInt256{true, cfg.gas_price};
  auto res = td::div((std::move(nanotomis) - cfg.flat_gas_price) << 16, gas_price256);
  return res->to_long() + cfg.flat_gas_limit;
}

static td::RefInt256 estimate_compute_gas_price(td::uint64 gas_used, const block::GasLimitsPrices& cfg) {
  auto gas_price256 = td::RefInt256{true, cfg.gas_price};
  return gas_used <= cfg.flat_gas_limit
             ? td::make_refint(cfg.flat_gas_price)
             : td::rshift(gas_price256 * (gas_used - cfg.flat_gas_limit), 16, 1) + cfg.flat_gas_price;
}

static vm::GasLimits estimate_compute_gas_limits(td::RefInt256 balance, const block::GasLimitsPrices& cfg) {
  vm::GasLimits res;
  res.gas_max = estimate_gas_bought_for(balance, estimate_compute_threshold(cfg), cfg);
  res.gas_credit = 0;
  res.gas_limit = estimate_gas_bought_for(td::make_refint(0), estimate_compute_threshold(cfg), cfg);
  res.gas_credit = std::min(static_cast<td::int64>(cfg.gas_credit), static_cast<td::int64>(res.gas_max));
  return res;
}

static td::Result<td::int64> estimate_calc_fwd_fees(td::Ref<vm::Cell> list, block::MsgPrices** msg_prices,
                                                    bool is_masterchain) {
  td::int64 res = 0;
  std::vector<td::Ref<vm::Cell>> actions;
  int n = 0;
  int max_actions = 20;
  while (true) {
    actions.push_back(list);
    auto cs = load_cell_slice(std::move(list));
    if (!cs.size_ext()) {
      break;
    }
    if (!cs.have_refs()) {
      return td::Status::Error("action list invalid: entry found with data but no next reference");
    }
    list = cs.prefetch_ref();
    if (++n > max_actions) {
      return td::Status::Error(PSTRING() << "action list too long: more than " << max_actions << " actions");
    }
  }
  for (int i = n - 1; i >= 0; --i) {
    vm::CellSlice cs = load_cell_slice(actions[i]);
    CHECK(cs.fetch_ref().not_null());
    int tag = block::gen::t_OutAction.get_tag(cs);
    CHECK(tag >= 0);
    switch (tag) {
      case block::gen::OutAction::action_set_code:
        return td::Status::Error("estimate_fee: action_set_code unsupported");
      case block::gen::OutAction::action_send_msg: {
        block::gen::OutAction::Record_action_send_msg act_rec;
        if (!tlb::unpack_exact(cs, act_rec) || (act_rec.mode & ~0xf3) || (act_rec.mode & 0xc0) == 0xc0) {
          return td::Status::Error("estimate_fee: can't parse send_msg");
        }
        block::gen::MessageRelaxed::Record msg;
        if (!tlb::type_unpack_cell(act_rec.out_msg, block::gen::t_MessageRelaxed_Any, msg)) {
          return td::Status::Error("estimate_fee: can't parse send_msg");
        }

        bool dest_is_masterchain = false;
        if (block::gen::t_CommonMsgInfoRelaxed.get_tag(*msg.info) == block::gen::CommonMsgInfoRelaxed::int_msg_info) {
          block::gen::CommonMsgInfoRelaxed::Record_int_msg_info info;
          if (!tlb::csr_unpack(msg.info, info)) {
            return td::Status::Error("estimate_fee: can't parse send_msg");
          }
          auto dest_addr = info.dest;
          if (!dest_addr->prefetch_ulong(1)) {
            return td::Status::Error("estimate_fee: messages with external addresses are unsupported");
          }
          int addr_tag = block::gen::t_MsgAddressInt.get_tag(*dest_addr);
          if (addr_tag == block::gen::MsgAddressInt::addr_std) {
            block::gen::MsgAddressInt::Record_addr_std recs;
            if (!tlb::csr_unpack(dest_addr, recs)) {
              return td::Status::Error("estimate_fee: can't parse send_msg");
            }
            dest_is_masterchain = recs.workchain_id == tos::masterchainId;
          }
        }

        vm::CellStorageStat sstat;
        sstat.add_used_storage(msg.init, true, 3);
        sstat.add_used_storage(msg.body, true, 3);
        res += msg_prices[is_masterchain || dest_is_masterchain]->compute_fwd_fees(sstat.cells, sstat.bits);
        break;
      }
      case block::gen::OutAction::action_reserve_currency:
        continue;
    }
  }
  return res;
}

static std::string build_estimate_fee_json(td::int64 in_fwd_fee, td::int64 storage_fee,
                                           td::int64 gas_fee, td::int64 fwd_fee) {
  return PSTRING()
      << "{\"@type\":\"query.fees\""
      << ",\"source_fees\":{\"@type\":\"fees\""
      << ",\"in_fwd_fee\":" << in_fwd_fee
      << ",\"storage_fee\":" << storage_fee
      << ",\"gas_fee\":" << gas_fee
      << ",\"fwd_fee\":" << fwd_fee << "}"
      << ",\"destination_fees\":[]}";
}

// Sends getMasterchainInfo (or lookupBlock if seqno given) + getAccountState, then returns parsed result
void JsonRpcServer::handle_getAddressInformation(td::JsonObject &params, std::string req_id,
                                                 td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();
  auto addr_str = params.get_required_string_field("address").ok();

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return result
  auto do_get_account = [addr, addr_str = std::move(addr_str), self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
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
            [addr, addr_str = std::move(addr_str), req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "getAccountState: " << R.error(), req_id_inner));
        return;
      }
      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse accountState: " << F.error(), req_id_inner));
        return;
      }
      auto f = F.move_as_ok();
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      promise_inner.set_value(make_json_ok(parsed.ok().to_address_info_json(), req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_get_account(std::move(lb->id_), std::move(req_id), std::move(promise));
        });
  } else {
    // Step 1b: getMasterchainInfo to get latest block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
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
          do_get_account(std::move(mc.ok()->last_), std::move(req_id), std::move(promise));
        });
  }
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

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return result
  auto do_get_account = [addr, addr_str = std::move(addr_str), self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
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
            [addr, addr_str = std::move(addr_str), req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "getAccountState: " << R.error(), req_id_inner));
        return;
      }
      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse accountState: " << F.error(), req_id_inner));
        return;
      }
      auto f = F.move_as_ok();
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      promise_inner.set_value(make_json_ok(parsed.ok().to_extended_info_json(addr_str), req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_get_account(std::move(lb->id_), std::move(req_id), std::move(promise));
        });
  } else {
    // Step 1b: getMasterchainInfo to get latest block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
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
          do_get_account(std::move(mc.ok()->last_), std::move(req_id), std::move(promise));
        });
  }
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

  // Parse optional stack parameter (array of ["type", "value"] pairs)
  vm::Stack stack;
  auto stack_r = params.extract_field("stack");
  if (stack_r.type() == td::JsonValue::Type::Array) {
    auto& arr = stack_r.get_array();
    for (auto& entry : arr) {
      if (entry.type() != td::JsonValue::Type::Array) continue;
      auto& pair = entry.get_array();
      if (pair.size() < 2) continue;
      if (pair[0].type() != td::JsonValue::Type::String) continue;
      auto type_str = pair[0].get_string().str();
      if (type_str == "num" || type_str == "tvm.Number") {
        std::string val_str;
        if (pair[1].type() == td::JsonValue::Type::String) {
          val_str = pair[1].get_string().str();
        } else if (pair[1].type() == td::JsonValue::Type::Number) {
          val_str = pair[1].get_number().str();
        } else {
          continue;
        }
        auto num = td::string_to_int256(val_str);
        if (num.not_null()) {
          stack.push(vm::StackEntry(std::move(num)));
        }
      } else if (type_str == "cell" || type_str == "tvm.Cell") {
        std::string b64;
        if (pair[1].type() == td::JsonValue::Type::Object) {
          auto bytes_r = pair[1].get_object().get_required_string_field("bytes");
          if (bytes_r.is_ok()) b64 = bytes_r.ok();
        } else if (pair[1].type() == td::JsonValue::Type::String) {
          b64 = pair[1].get_string().str();
        }
        if (!b64.empty()) {
          auto decoded = td::base64_decode(b64);
          if (decoded.is_ok()) {
            auto cell = vm::std_boc_deserialize(td::Slice(decoded.ok()));
            if (cell.is_ok()) {
              stack.push(vm::StackEntry(cell.move_as_ok()));
            }
          }
        }
      } else if (type_str == "slice" || type_str == "tvm.Slice") {
        std::string b64;
        if (pair[1].type() == td::JsonValue::Type::Object) {
          auto bytes_r = pair[1].get_object().get_required_string_field("bytes");
          if (bytes_r.is_ok()) b64 = bytes_r.ok();
        } else if (pair[1].type() == td::JsonValue::Type::String) {
          b64 = pair[1].get_string().str();
        }
        if (!b64.empty()) {
          auto decoded = td::base64_decode(b64);
          if (decoded.is_ok()) {
            auto cell = vm::std_boc_deserialize(td::Slice(decoded.ok()));
            if (cell.is_ok()) {
              stack.push(vm::StackEntry(vm::load_cell_slice_ref(cell.move_as_ok())));
            }
          }
        }
      }
    }
  }

  // Serialize stack as params
  vm::CellBuilder cb;
  if (!stack.serialize(cb)) {
    promise.set_value(make_json_error(-32603, "stack serialize error", req_id));
    return;
  }
  auto params_boc_r = vm::std_boc_serialize(cb.finalize());
  if (params_boc_r.is_error()) {
    promise.set_value(make_json_error(-32603, "params BOC error", req_id));
    return;
  }

  // Optional seqno: query at a specific MC block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto params_boc = params_boc_r.move_as_ok();

  // Step 2 lambda: runSmcMethod at a resolved block
  auto do_run_method = [addr, method_id, params_boc = std::move(params_boc),
                        req_id = std::move(req_id), self_id = actor_id(this),
                        promise = std::move(promise)](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id) mutable {
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                0x04, std::move(block_id),
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
  };  // end of do_run_method

  // Step 1: resolve block
  if (has_seqno) {
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0), true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    send_liteserver_query(std::move(lookup_query),
        [do_run_method = std::move(do_run_method)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) return;
          do_run_method(std::move(lb_r.move_as_ok()->id_));
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_run_method = std::move(do_run_method)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) return;
          do_run_method(std::move(mc_r.move_as_ok()->last_));
        });
  }
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

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 req_seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState, detect wallet, query wallet seqno
  auto do_get_account = [addr, self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
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
             req_id_inner = std::move(req_id_inner), self_id,
             promise_inner = std::move(promise_inner)](
                td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "getAccountState: " << R.error(), req_id_inner));
        return;
      }

      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse accountState: " << F.error(), req_id_inner));
        return;
      }
      auto f = F.move_as_ok();
      auto parsed_r = ParsedAccountState::parse(f, addr);
      if (parsed_r.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed_r.error(), req_id_inner));
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
        promise_inner.set_value(make_json_ok(
            build_wallet_json(false, parsed.balance, parsed.state_str, "",
                              -1, parsed.last_trans_lt, parsed.last_trans_hash_b64),
            req_id_inner));
        return;
      }

      // Is a wallet — query seqno via runGetMethod
      td::int64 method_id = (td::crc16(td::Slice("seqno")) & 0xffff) | 0x10000;
      vm::CellBuilder cb;
      vm::Stack empty_stack;
      empty_stack.serialize(cb);
      auto params_boc = vm::std_boc_serialize(cb.finalize());
      if (params_boc.is_error()) {
        promise_inner.set_value(make_json_ok(
            build_wallet_json(true, parsed.balance, parsed.state_str, wallet_type,
                              -1, parsed.last_trans_lt, parsed.last_trans_hash_b64),
            req_id_inner));
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
               req_id_inner = std::move(req_id_inner), promise_inner = std::move(promise_inner)](
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
        promise_inner.set_value(make_json_ok(
            build_wallet_json(true, balance, account_state, wallet_type,
                              seqno, last_lt, last_hash),
            req_id_inner));
      }));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), req_seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_get_account(std::move(lb->id_), std::move(req_id), std::move(promise));
        });
  } else {
    // Step 1b: getMasterchainInfo to get latest block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
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
          do_get_account(std::move(mc.ok()->last_), std::move(req_id), std::move(promise));
        });
  }
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
    // Try 'unixtime' as alias for 'utime'
    auto unixtime_r = params.get_optional_int_field("unixtime");
    if (unixtime_r.is_ok() && unixtime_r.ok() > 0) {
      mode = 4;
      utime = static_cast<td::int32>(unixtime_r.ok());
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
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
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

// ─── getConsensusBlock ────────────────────────────────────────────────

void JsonRpcServer::handle_getConsensusBlock(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  td::actor::send_closure(
      validator_manager_, &validator::ValidatorManagerInterface::get_last_liteserver_state_block,
      td::PromiseCreator::lambda(
          [this, req_id = std::move(req_id), promise = std::move(promise)](
              td::Result<std::pair<td::Ref<validator::MasterchainState>, BlockIdExt>> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getConsensusBlock: " << R.error(), req_id));
          return;
        }
        auto [state, block_id] = R.move_as_ok();
        td::uint32 seqno = block_id.seqno();
        if (consensus_block_seqno_ != seqno) {
          consensus_block_seqno_ = seqno;
          consensus_block_timestamp_ = static_cast<td::int64>(td::Clocks::system());
        } else if (consensus_block_timestamp_ == 0) {
          consensus_block_timestamp_ = static_cast<td::int64>(td::Clocks::system());
        }

        td::StringBuilder sb;
        sb << "{\"consensus_block\":" << consensus_block_seqno_
           << ",\"timestamp\":" << consensus_block_timestamp_;
        if (state.not_null()) {
          sb << ",\"last_block_utime\":" << state->get_unix_time();
        }
        sb << "}";
        promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
      }));
}

// ─── shards ──────────────────────────────────────────────────────────

void JsonRpcServer::handle_shards(td::JsonObject &params, std::string req_id,
                                  td::Promise<HttpReturn> promise) {
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;

  auto self_id = actor_id(this);

  // Step 2 lambda: given a resolved block ID, fetch shard hashes
  auto do_get_shards = [self_id, req_id = std::move(req_id),
                        promise = std::move(promise)](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> resolved_block_id) mutable {
        // Fetch a block header proof that includes BlockExtra and
        // ShardHashes (mode = 16 | 32 = 48). This avoids total-state download
        // limits and the broken getAllShardsInfo path while staying within the
        // standard liteserver RPC surface.
        auto header_inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getBlockHeader>(
                std::move(resolved_block_id), 48),
            true);
        auto header_query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(header_inner)), true);

        td::actor::send_closure(
            self_id, &JsonRpcServer::send_liteserver_query, std::move(header_query),
            td::PromiseCreator::lambda(
                [req_id = std::move(req_id), promise = std::move(promise)](
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

          auto proof_root_r = vm::std_boc_deserialize(hdr->header_proof_.as_slice());
          if (proof_root_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "deserialize header_proof: " << proof_root_r.error(), req_id));
            return;
          }
          auto virt_r = vm::MerkleProof::virtualize(proof_root_r.move_as_ok());
          if (virt_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "virtualize header_proof: " << virt_r.error(), req_id));
            return;
          }
          auto block_root = virt_r.move_as_ok();
          auto blk_id = tos::create_block_id(hdr->id_);
          auto check_r = block::check_block_header_proof(block_root, blk_id);
          if (check_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "header proof error: " << check_r, req_id));
            return;
          }

          block::gen::Block::Record blk;
          block::gen::BlockExtra::Record extra;
          block::gen::McBlockExtra::Record mc_extra;
          if (!tlb::unpack_cell(block_root, blk) || !tlb::unpack_cell(blk.extra, extra) ||
              !extra.custom->have_refs() ||
              !tlb::unpack_cell(extra.custom->prefetch_ref(), mc_extra)) {
            promise.set_value(make_json_error(-32603,
                "failed to extract shard hashes from block header proof", req_id));
            return;
          }

          block::ShardConfig sc;
          if (!mc_extra.shard_hashes->have_refs() ||
              !sc.unpack(mc_extra.shard_hashes->prefetch_ref())) {
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
            return 0;
          });
          sb << "]}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
        }));
  };  // end of do_get_shards

  // Step 1: resolve block
  if (has_seqno) {
    td::int32 seqno = static_cast<td::int32>(seqno_r.ok());
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    send_liteserver_query(std::move(lookup_query),
        [do_get_shards = std::move(do_get_shards)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) return;
          do_get_shards(std::move(lb_r.move_as_ok()->id_));
        });
  } else {
    // No seqno provided — query latest masterchain block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_get_shards = std::move(do_get_shards)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) return;
          do_get_shards(std::move(mc_r.move_as_ok()->last_));
        });
  }
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
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
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

// ─── getMasterchainBlockSignatures ──────────────────────────────────────

void JsonRpcServer::handle_getMasterchainBlockSignatures(td::JsonObject &params, std::string req_id,
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
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
          return;
        }
        auto lb = lb_r.move_as_ok();
        auto resolved_id_json = format_block_id_json(*lb->id_);

        // Step 2: getBlockProof with mode=0 (no target — proof from known block back to init).
        // The proof chain contains forward links with validator signatures.
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getBlockProof>(
                0, std::move(lb->id_), nullptr),
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
                PSTRING() << "getBlockProof: " << R.error(), req_id));
            return;
          }
          auto proof_r = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(
              R.move_as_ok(), true);
          if (proof_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse blockProof: " << proof_r.error(), req_id));
            return;
          }
          auto proof = proof_r.move_as_ok();

          // Extract signatures from forward links in the proof chain.
          // Forward links (liteServer_blockLinkForward) contain a SignatureSet
          // with the validator signatures for the destination block.
          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.masterchainBlockSignatures\",\"id\":" << id_json
             << ",\"signatures\":[";
          bool first_sig = true;
          for (auto& step : proof->steps_) {
            if (step->get_id() == tos::lite_api::liteServer_blockLinkForward::ID) {
              auto* fwd = static_cast<tos::lite_api::liteServer_blockLinkForward*>(step.get());
              if (fwd->signatures_ &&
                  fwd->signatures_->get_id() == tos::lite_api::liteServer_signatureSet_ordinary::ID) {
                auto* sig_set = static_cast<tos::lite_api::liteServer_signatureSet_ordinary*>(
                    fwd->signatures_.get());
                for (auto& sig : sig_set->signatures_) {
                  if (!first_sig) sb << ",";
                  first_sig = false;
                  sb << "{\"node_id_short\":\""
                     << td::base64_encode(sig->node_id_short_.as_slice())
                     << "\",\"signature\":\""
                     << td::base64_encode(sig->signature_.as_slice())
                     << "\"}";
                }
              }
            }
          }
          sb << "]}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
        }));
      });
}

// ─── getShardBlockProof ─────────────────────────────────────────────────

void JsonRpcServer::handle_getShardBlockProof(td::JsonObject &params, std::string req_id,
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

  // Step 1: lookupBlock to resolve the full block ID
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
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
            R.move_as_ok(), true);
        if (lb_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
          return;
        }
        auto lb = lb_r.move_as_ok();

        // Step 2: getShardBlockProof
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getShardBlockProof>(
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
                PSTRING() << "getShardBlockProof: " << R.error(), req_id));
            return;
          }
          auto sbp_r = tos::fetch_tl_object<tos::lite_api::liteServer_shardBlockProof>(
              R.move_as_ok(), true);
          if (sbp_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse shardBlockProof: " << sbp_r.error(), req_id));
            return;
          }
          auto sbp = sbp_r.move_as_ok();

          td::StringBuilder sb;
          sb << "{\"@type\":\"blocks.shardBlockProof\""
             << ",\"masterchain_id\":" << format_block_id_json(*sbp->masterchain_id_)
             << ",\"links\":[";
          bool first = true;
          for (auto& link : sbp->links_) {
            if (!first) sb << ",";
            first = false;
            sb << "{\"id\":" << format_block_id_json(*link->id_)
               << ",\"proof\":\"" << td::base64_encode(link->proof_.as_slice()) << "\""
               << "}";
          }
          sb << "]}";
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
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
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
        auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
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

// ─── Transaction lookup helpers ─────────────────────────────────────────
// Shared by tryLocateTx, tryLocateResultTx, tryLocateSourceTx.

// Parse the three common parameters: source, destination, created_lt.
struct LocateParams {
  block::StdAddress source;
  block::StdAddress destination;
  td::uint64 created_lt;
};

static td::Result<LocateParams> parse_locate_params(td::JsonObject &params) {
  auto src_r = params.get_required_string_field("source");
  if (src_r.is_error()) return td::Status::Error("Missing 'source'");
  auto dst_r = params.get_required_string_field("destination");
  if (dst_r.is_error()) return td::Status::Error("Missing 'destination'");
  auto lt_r = params.get_required_string_field("created_lt");
  if (lt_r.is_error()) {
    // Try 'lt' as alias for 'created_lt'
    lt_r = params.get_required_string_field("lt");
  }
  if (lt_r.is_error()) return td::Status::Error("Missing 'created_lt' or 'lt'");

  LocateParams lp;
  if (!lp.source.parse_addr(td::Slice(src_r.ok())))
    return td::Status::Error("Invalid 'source' address");
  if (!lp.destination.parse_addr(td::Slice(dst_r.ok())))
    return td::Status::Error("Invalid 'destination' address");
  lp.created_lt = std::strtoull(lt_r.ok().c_str(), nullptr, 10);
  if (lp.created_lt == 0)
    return td::Status::Error("Invalid 'created_lt' (must be > 0)");
  return lp;
}

// Extract source address from a message cell.  Returns false if the message
// is not an internal message or cannot be parsed.
static bool msg_get_src_addr(td::Ref<vm::Cell> msg_cell, block::StdAddress &out) {
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(msg_cell, block::gen::t_Message_Any, message)) return false;
  auto tag = block::gen::CommonMsgInfo().get_tag(*message.info);
  if (tag != block::gen::CommonMsgInfo::int_msg_info) return false;
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  if (!tlb::csr_unpack(message.info, info)) return false;
  block::gen::MsgAddressInt::Record_addr_std addr;
  if (!tlb::csr_unpack(info.src, addr)) return false;
  out.workchain = addr.workchain_id;
  out.addr = addr.address;
  return true;
}

// Extract destination address from a message cell.
static bool msg_get_dst_addr(td::Ref<vm::Cell> msg_cell, block::StdAddress &out) {
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(msg_cell, block::gen::t_Message_Any, message)) return false;
  auto tag = block::gen::CommonMsgInfo().get_tag(*message.info);
  if (tag != block::gen::CommonMsgInfo::int_msg_info) return false;
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  if (!tlb::csr_unpack(message.info, info)) return false;
  block::gen::MsgAddressInt::Record_addr_std addr;
  if (!tlb::csr_unpack(info.dest, addr)) return false;
  out.workchain = addr.workchain_id;
  out.addr = addr.address;
  return true;
}

// Extract created_lt from a message cell (internal messages only).
static bool msg_get_created_lt(td::Ref<vm::Cell> msg_cell, td::uint64 &out) {
  block::gen::Message::Record message;
  if (!tlb::type_unpack_cell(msg_cell, block::gen::t_Message_Any, message)) return false;
  auto tag = block::gen::CommonMsgInfo().get_tag(*message.info);
  if (tag != block::gen::CommonMsgInfo::int_msg_info) return false;
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  if (!tlb::csr_unpack(message.info, info)) return false;
  out = info.created_lt;
  return true;
}

// Build a "blocks.transaction" JSON result from a matching transaction root cell
// and its block ID.
static std::string format_located_tx_json(
    const block::StdAddress &source,
    const block::StdAddress &destination,
    td::Ref<vm::Cell> tx_root,
    const tos::lite_api::tosNode_blockIdExt &blk) {
  block::gen::Transaction::Record tx;
  td::uint64 lt = 0;
  if (tlb::unpack_cell(tx_root, tx)) {
    lt = tx.lt;
  }
  auto hash_b64 = td::base64_encode(tx_root->get_hash(0).as_slice());

  return PSTRING()
      << "{\"@type\":\"blocks.transaction\""
      << ",\"source\":" << td::JsonString(td::Slice(source.rserialize(true)))
      << ",\"destination\":" << td::JsonString(td::Slice(destination.rserialize(true)))
      << ",\"lt\":\"" << lt << "\""
      << ",\"hash\":\"" << hash_b64 << "\""
      << ",\"block_id\":" << format_block_id_json(blk)
      << "}";
}

// ─── tryLocateTx ────────────────────────────────────────────────────────
// Locate a transaction on the destination account that has an incoming
// message matching (source, created_lt).

void JsonRpcServer::handle_tryLocateTx(td::JsonObject &params, std::string req_id,
                                       td::Promise<HttpReturn> promise) {
  auto lp_r = parse_locate_params(params);
  if (lp_r.is_error()) {
    promise.set_value(make_json_error(-32602, lp_r.error().message().str(), req_id));
    return;
  }
  auto lp = lp_r.move_as_ok();

  // Step 1: Get account state to find last transaction lt/hash
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [lp, req_id = std::move(req_id), self_id,
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

        // Get account state for destination to find last transaction
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc.ok()->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    lp.destination.workchain, lp.destination.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [lp, req_id = std::move(req_id), self_id,
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

          // Validate and extract last_trans_lt, last_trans_hash
          auto blk_id = tos::create_block_id(f->id_);
          auto shard_blk_id = tos::create_block_id(f->shardblk_);
          block::AccountState as;
          as.blk = blk_id;
          as.shard_blk = shard_blk_id;
          as.shard_proof = f->shard_proof_.clone();
          as.proof = f->proof_.clone();
          as.state = f->state_.clone();
          auto info_r = as.validate(blk_id, lp.destination);
          if (info_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "validate account state: " << info_r.error(), req_id));
            return;
          }
          auto info = info_r.move_as_ok();
          if (info.last_trans_lt == 0) {
            promise.set_value(make_json_error(-32603,
                "Destination account has no transactions", req_id));
            return;
          }

          // Step 2: Get last 20 transactions for the destination account
          auto tx_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
                  20,
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      lp.destination.workchain, lp.destination.addr),
                  static_cast<td::int64>(info.last_trans_lt), info.last_trans_hash),
              true);
          auto tx_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(tx_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(tx_query),
              td::PromiseCreator::lambda(
                  [lp, req_id = std::move(req_id),
                   promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
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

            if (tl->transactions_.empty()) {
              promise.set_value(make_json_error(-32603,
                  "Transaction not found in recent history", req_id));
              return;
            }

            auto roots_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
            if (roots_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  "Failed to deserialize transactions BOC", req_id));
              return;
            }
            auto roots = roots_r.move_as_ok();

            // Search for a transaction whose in_msg has matching source + created_lt
            for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
              block::gen::Transaction::Record tx;
              if (!tlb::unpack_cell(roots[i], tx)) continue;

              // Check in_msg (Maybe ^Message)
              auto is_just = tx.r1.in_msg->prefetch_long(1);
              if (is_just != -1) continue;  // no in_msg

              auto msg_cell = tx.r1.in_msg->prefetch_ref();
              if (msg_cell.is_null()) continue;

              block::StdAddress msg_src;
              td::uint64 msg_lt = 0;
              if (!msg_get_src_addr(msg_cell, msg_src)) continue;
              if (!msg_get_created_lt(msg_cell, msg_lt)) continue;

              if (msg_src.workchain == lp.source.workchain &&
                  msg_src.addr == lp.source.addr &&
                  msg_lt == lp.created_lt) {
                // Found the matching transaction
                promise.set_value(make_json_ok(
                    format_located_tx_json(lp.source, lp.destination, roots[i], *tl->ids_[i]),
                    req_id));
                return;
              }
            }

            promise.set_value(make_json_error(-32603,
                "Transaction not found in recent history (searched 20 transactions)", req_id));
          }));
        }));
      });
}

// ─── tryLocateResultTx ──────────────────────────────────────────────────
// Given an outgoing message (source account sent at created_lt), find the
// resulting transaction on the destination that processed it.

void JsonRpcServer::handle_tryLocateResultTx(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  auto lp_r = parse_locate_params(params);
  if (lp_r.is_error()) {
    promise.set_value(make_json_error(-32602, lp_r.error().message().str(), req_id));
    return;
  }
  auto lp = lp_r.move_as_ok();

  // Step 1: Get account state for the DESTINATION to find its last transaction
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [lp, req_id = std::move(req_id), self_id,
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

        // Get account state for destination
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc.ok()->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    lp.destination.workchain, lp.destination.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [lp, req_id = std::move(req_id), self_id,
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

          auto blk_id = tos::create_block_id(f->id_);
          auto shard_blk_id = tos::create_block_id(f->shardblk_);
          block::AccountState as;
          as.blk = blk_id;
          as.shard_blk = shard_blk_id;
          as.shard_proof = f->shard_proof_.clone();
          as.proof = f->proof_.clone();
          as.state = f->state_.clone();
          auto info_r = as.validate(blk_id, lp.destination);
          if (info_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "validate account state: " << info_r.error(), req_id));
            return;
          }
          auto info = info_r.move_as_ok();
          if (info.last_trans_lt == 0) {
            promise.set_value(make_json_error(-32603,
                "Destination account has no transactions", req_id));
            return;
          }

          // Step 2: Get destination transactions and search for one whose in_msg
          // matches source + created_lt (same as tryLocateTx — the "result" tx is
          // the transaction that RECEIVED the message sent from source at created_lt)
          auto tx_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
                  20,
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      lp.destination.workchain, lp.destination.addr),
                  static_cast<td::int64>(info.last_trans_lt), info.last_trans_hash),
              true);
          auto tx_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(tx_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(tx_query),
              td::PromiseCreator::lambda(
                  [lp, req_id = std::move(req_id),
                   promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
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

            if (tl->transactions_.empty()) {
              promise.set_value(make_json_error(-32603,
                  "Transaction not found in recent history", req_id));
              return;
            }

            auto roots_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
            if (roots_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  "Failed to deserialize transactions BOC", req_id));
              return;
            }
            auto roots = roots_r.move_as_ok();

            // Search: the result tx is on destination with in_msg from source at created_lt
            for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
              block::gen::Transaction::Record tx;
              if (!tlb::unpack_cell(roots[i], tx)) continue;

              auto is_just = tx.r1.in_msg->prefetch_long(1);
              if (is_just != -1) continue;

              auto msg_cell = tx.r1.in_msg->prefetch_ref();
              if (msg_cell.is_null()) continue;

              block::StdAddress msg_src;
              td::uint64 msg_lt = 0;
              if (!msg_get_src_addr(msg_cell, msg_src)) continue;
              if (!msg_get_created_lt(msg_cell, msg_lt)) continue;

              if (msg_src.workchain == lp.source.workchain &&
                  msg_src.addr == lp.source.addr &&
                  msg_lt == lp.created_lt) {
                promise.set_value(make_json_ok(
                    format_located_tx_json(lp.source, lp.destination, roots[i], *tl->ids_[i]),
                    req_id));
                return;
              }
            }

            promise.set_value(make_json_error(-32603,
                "Result transaction not found in recent history (searched 20 transactions)", req_id));
          }));
        }));
      });
}

// ─── tryLocateSourceTx ──────────────────────────────────────────────────
// Given an incoming message (destination received at created_lt), find the
// source transaction that sent it.  We search the source account's
// transactions for one that has an outgoing message to destination with
// matching created_lt.

void JsonRpcServer::handle_tryLocateSourceTx(td::JsonObject &params, std::string req_id,
                                             td::Promise<HttpReturn> promise) {
  auto lp_r = parse_locate_params(params);
  if (lp_r.is_error()) {
    promise.set_value(make_json_error(-32602, lp_r.error().message().str(), req_id));
    return;
  }
  auto lp = lp_r.move_as_ok();

  // Step 1: Get account state for the SOURCE to find its last transaction
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [lp, req_id = std::move(req_id), self_id,
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

        // Get account state for source
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc.ok()->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    lp.source.workchain, lp.source.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [lp, req_id = std::move(req_id), self_id,
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

          auto blk_id = tos::create_block_id(f->id_);
          auto shard_blk_id = tos::create_block_id(f->shardblk_);
          block::AccountState as;
          as.blk = blk_id;
          as.shard_blk = shard_blk_id;
          as.shard_proof = f->shard_proof_.clone();
          as.proof = f->proof_.clone();
          as.state = f->state_.clone();
          auto info_r = as.validate(blk_id, lp.source);
          if (info_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "validate account state: " << info_r.error(), req_id));
            return;
          }
          auto info = info_r.move_as_ok();
          if (info.last_trans_lt == 0) {
            promise.set_value(make_json_error(-32603,
                "Source account has no transactions", req_id));
            return;
          }

          // Step 2: Get source transactions and search for one whose out_msgs
          // contains a message to destination with matching created_lt
          auto tx_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
                  20,
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      lp.source.workchain, lp.source.addr),
                  static_cast<td::int64>(info.last_trans_lt), info.last_trans_hash),
              true);
          auto tx_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(tx_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(tx_query),
              td::PromiseCreator::lambda(
                  [lp, req_id = std::move(req_id),
                   promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
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

            if (tl->transactions_.empty()) {
              promise.set_value(make_json_error(-32603,
                  "Transaction not found in recent history", req_id));
              return;
            }

            auto roots_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
            if (roots_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  "Failed to deserialize transactions BOC", req_id));
              return;
            }
            auto roots = roots_r.move_as_ok();

            // Search: look for a source tx with an out_msg to destination at created_lt
            for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
              block::gen::Transaction::Record tx;
              if (!tlb::unpack_cell(roots[i], tx)) continue;

              if (tx.outmsg_cnt == 0) continue;

              // Iterate out_msgs dictionary
              vm::Dictionary dict{tx.r1.out_msgs, 15};
              for (int k = 0; k < tx.outmsg_cnt && k < 100; k++) {
                auto out_msg_ref = dict.lookup_ref(td::BitArray<15>{k});
                if (out_msg_ref.is_null()) continue;

                block::StdAddress msg_dst;
                td::uint64 msg_lt = 0;
                if (!msg_get_dst_addr(out_msg_ref, msg_dst)) continue;
                if (!msg_get_created_lt(out_msg_ref, msg_lt)) continue;

                if (msg_dst.workchain == lp.destination.workchain &&
                    msg_dst.addr == lp.destination.addr &&
                    msg_lt == lp.created_lt) {
                  // Found: the source transaction that sent this message
                  promise.set_value(make_json_ok(
                      format_located_tx_json(lp.source, lp.destination, roots[i], *tl->ids_[i]),
                      req_id));
                  return;
                }
              }
            }

            promise.set_value(make_json_error(-32603,
                "Source transaction not found in recent history (searched 20 transactions)", req_id));
          }));
        }));
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

void JsonRpcServer::handle_estimateFee(td::JsonObject &params, std::string req_id,
                                       td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto body_r = parse_optional_boc_field(params, "body");
  if (body_r.is_error()) {
    promise.set_value(make_json_error(-32602, body_r.error().message().str(), req_id));
    return;
  }
  if (body_r.ok().is_null()) {
    promise.set_value(make_json_error(-32602, "Missing 'body'", req_id));
    return;
  }
  auto init_code_r = parse_optional_boc_field(params, "init_code");
  if (init_code_r.is_error()) {
    promise.set_value(make_json_error(-32602, init_code_r.error().message().str(), req_id));
    return;
  }
  auto init_data_r = parse_optional_boc_field(params, "init_data");
  if (init_data_r.is_error()) {
    promise.set_value(make_json_error(-32602, init_data_r.error().message().str(), req_id));
    return;
  }
  auto ignore_chksig_r = params.get_optional_bool_field("ignore_chksig", true);
  if (ignore_chksig_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Invalid 'ignore_chksig'", req_id));
    return;
  }

  auto addr = addr_r.move_as_ok();
  auto body_cell = body_r.move_as_ok();
  auto init_code = init_code_r.move_as_ok();
  auto init_data = init_data_r.move_as_ok();
  auto ignore_chksig = ignore_chksig_r.move_as_ok();

  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [self_id, addr, body_cell = std::move(body_cell), init_code = std::move(init_code),
       init_data = std::move(init_data), ignore_chksig, req_id = std::move(req_id),
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getMasterchainInfo failed: " << R.error(), req_id));
          return;
        }
        auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
        if (mc_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse masterchainInfo: " << mc_r.error(), req_id));
          return;
        }
        auto mc = mc_r.move_as_ok();
        auto block_id = tos::create_block_id(mc->last_);
        auto account_inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                tos::create_tl_lite_block_id(block_id),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(addr.workchain, addr.addr)),
            true);
        auto account_query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(account_inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query, std::move(account_query),
            td::PromiseCreator::lambda(
                [self_id, addr, block_id = std::move(block_id), body_cell = std::move(body_cell),
                 init_code = std::move(init_code), init_data = std::move(init_data), ignore_chksig,
                 req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> account_res) mutable {
                  if (account_res.is_error()) {
                    promise.set_value(make_json_error(-32603,
                        PSTRING() << "getAccountState failed: " << account_res.error(), req_id));
                    return;
                  }
                  auto account_r =
                      tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(account_res.move_as_ok(), true);
                  if (account_r.is_error()) {
                    promise.set_value(make_json_error(-32603,
                        PSTRING() << "parse accountState: " << account_r.error(), req_id));
                    return;
                  }
                  auto account = account_r.move_as_ok();
                  auto parsed_r = ParsedAccountState::parse(account, addr);
                  if (parsed_r.is_error()) {
                    promise.set_value(make_json_error(-32603,
                        PSTRING() << "parse account proof: " << parsed_r.error(), req_id));
                    return;
                  }
                  auto parsed = parsed_r.move_as_ok();

                  td::Ref<vm::Cell> effective_code = init_code.not_null() ? init_code : parsed.code_cell;
                  td::Ref<vm::Cell> effective_data = init_data.not_null() ? init_data : parsed.data_cell;
                  td::Ref<vm::Cell> new_state;
                  if (effective_code.not_null() || effective_data.not_null()) {
                    new_state = tos::GenericAccount::get_init_state(effective_code, effective_data);
                  }
                  if (effective_code.is_null()) {
                    promise.set_value(make_json_error(-32603,
                        "estimateFee requires deploy init_code/init_data or an active account state", req_id));
                    return;
                  }

                  auto config_inner = tos::serialize_tl_object(
                      tos::create_tl_object<tos::lite_api::liteServer_getConfigAll>(
                          block::ConfigInfo::needPrevBlocks, tos::create_tl_lite_block_id(block_id)),
                      true);
                  auto config_query = tos::serialize_tl_object(
                      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(config_inner)), true);

                  td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query, std::move(config_query),
                      td::PromiseCreator::lambda(
                          [addr, body_cell = std::move(body_cell), new_state = std::move(new_state),
                           effective_code = std::move(effective_code), effective_data = std::move(effective_data),
                           parsed = std::move(parsed), ignore_chksig, req_id = std::move(req_id),
                           promise = std::move(promise)](td::Result<td::BufferSlice> config_res) mutable {
                            if (config_res.is_error()) {
                              promise.set_value(make_json_error(-32603,
                                  PSTRING() << "getConfigAll failed: " << config_res.error(), req_id));
                              return;
                            }
                            auto config_r =
                                tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(config_res.move_as_ok(), true);
                            if (config_r.is_error()) {
                              promise.set_value(make_json_error(-32603,
                                  PSTRING() << "parse configInfo: " << config_r.error(), req_id));
                              return;
                            }
                            auto config_info = config_r.move_as_ok();
                            auto requested_block_id = tos::create_block_id(config_info->id_);
                            auto state_root_r = block::check_extract_state_proof(
                                requested_block_id, config_info->state_proof_.as_slice(),
                                config_info->config_proof_.as_slice());
                            if (state_root_r.is_error()) {
                              promise.set_value(make_json_error(-32603,
                                  PSTRING() << "config proof error: " << state_root_r.error(), req_id));
                              return;
                            }
                            auto cfg_r = block::ConfigInfo::extract_config(
                                state_root_r.move_as_ok(), requested_block_id,
                                block::ConfigInfo::needPrevBlocks | block::ConfigInfo::needCapabilities |
                                    block::ConfigInfo::needLibraries);
                            if (cfg_r.is_error()) {
                              promise.set_value(make_json_error(-32603,
                                  PSTRING() << "config extract error: " << cfg_r.error(), req_id));
                              return;
                            }
                            auto cfg = cfg_r.move_as_ok();
                            auto prev_blocks_r = cfg->get_prev_blocks_info();
                            if (prev_blocks_r.is_error()) {
                              promise.set_value(make_json_error(-32603,
                                  PSTRING() << "prev_blocks_info error: " << prev_blocks_r.error(), req_id));
                              return;
                            }

                            bool is_masterchain = addr.workchain == tos::masterchainId;
                            auto gas_limits_prices_r = cfg->get_gas_limits_prices(is_masterchain);
                            auto storage_prices_r = cfg->get_storage_prices();
                            auto masterchain_msg_prices_r = cfg->get_msg_prices(true);
                            auto basechain_msg_prices_r = cfg->get_msg_prices(false);
                            if (gas_limits_prices_r.is_error() || storage_prices_r.is_error() ||
                                masterchain_msg_prices_r.is_error() || basechain_msg_prices_r.is_error()) {
                              promise.set_value(make_json_error(-32603, "fee config unavailable", req_id));
                              return;
                            }
                            auto gas_limits_prices = gas_limits_prices_r.move_as_ok();
                            auto storage_prices = storage_prices_r.move_as_ok();
                            auto masterchain_msg_prices = masterchain_msg_prices_r.move_as_ok();
                            auto basechain_msg_prices = basechain_msg_prices_r.move_as_ok();
                            block::MsgPrices* msg_prices[2] = {&basechain_msg_prices, &masterchain_msg_prices};

                            auto storage_fee_256 = block::StoragePrices::compute_storage_fees(
                                parsed.sync_utime, storage_prices, parsed.storage_used,
                                parsed.storage_last_paid, false, is_masterchain);
                            auto storage_fee = storage_fee_256.is_null() ? 0 : storage_fee_256->to_long();

                            auto message = tos::GenericAccount::create_ext_message(addr, new_state, body_cell);
                            vm::CellStorageStat in_msg_stat;
                            in_msg_stat.add_used_storage(message, true, 3);
                            auto in_fwd_fee =
                                msg_prices[is_masterchain]->compute_fwd_fees(in_msg_stat.cells, in_msg_stat.bits);

                            vm::Dictionary libraries{256};
                            if (cfg->get_libraries_root().not_null()) {
                              libraries = vm::Dictionary(cfg->get_libraries_root(), 256);
                            }

                            auto prev_blocks_info = prev_blocks_r.move_as_ok();
                            auto cfg_shared = std::shared_ptr<const block::Config>(cfg.release());
                            auto smc = tos::SmartContract::create({effective_code, effective_data});
                            auto gas_limits =
                                estimate_compute_gas_limits(td::make_refint(parsed.balance), gas_limits_prices);
                            auto run_res = smc.write().send_external_message(
                                body_cell,
                                tos::SmartContract::Args()
                                    .set_limits(gas_limits)
                                    .set_balance(parsed.balance)
                                    .set_extra_currencies(parsed.extra_currencies_cell)
                                    .set_now(parsed.sync_utime)
                                    .set_ignore_chksig(ignore_chksig)
                                    .set_address(addr)
                                    .set_config(cfg_shared)
                                    .set_prev_blocks_info(prev_blocks_info)
                                    .set_libraries(std::move(libraries)));

                            td::int64 fwd_fee = 0;
                            if (run_res.success) {
                              auto fwd_fee_r = estimate_calc_fwd_fees(run_res.actions, msg_prices, is_masterchain);
                              if (fwd_fee_r.is_error()) {
                                promise.set_value(make_json_error(-32603,
                                    PSTRING() << "forward fee error: " << fwd_fee_r.error(), req_id));
                                return;
                              }
                              fwd_fee = fwd_fee_r.move_as_ok();
                            }

                            auto gas_fee = run_res.accepted
                                               ? estimate_compute_gas_price(run_res.gas_used, gas_limits_prices)->to_long()
                                               : 0;
                            promise.set_value(make_json_ok(
                                build_estimate_fee_json(in_fwd_fee, storage_fee, gas_fee, fwd_fee), req_id));
                          }));
                }));
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

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return balance
  auto do_get_account = [addr, self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
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
            [addr, req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "getAccountState: " << R.error(), req_id_inner));
        return;
      }
      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse accountState: " << F.error(), req_id_inner));
        return;
      }
      auto f = F.move_as_ok();
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      promise_inner.set_value(make_json_ok(
          PSTRING() << "\"" << parsed.ok().balance << "\"", req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_get_account(std::move(lb->id_), std::move(req_id), std::move(promise));
        });
  } else {
    // Step 1b: getMasterchainInfo to get latest block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
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
          do_get_account(std::move(mc.ok()->last_), std::move(req_id), std::move(promise));
        });
  }
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

  // Optional seqno parameter — query account state at a specific masterchain block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto self_id = actor_id(this);

  // Step 2: given a resolved block ID, query getAccountState and return state string
  auto do_get_account = [addr, self_id](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id,
      std::string req_id_inner, td::Promise<HttpReturn> promise_inner) mutable {
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
            [addr, req_id_inner = std::move(req_id_inner),
             promise_inner = std::move(promise_inner)](td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "getAccountState: " << R.error(), req_id_inner));
        return;
      }
      auto F = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(
          R.move_as_ok(), true);
      if (F.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse accountState: " << F.error(), req_id_inner));
        return;
      }
      auto f = F.move_as_ok();
      auto parsed = ParsedAccountState::parse(f, addr);
      if (parsed.is_error()) {
        promise_inner.set_value(make_json_error(-32603,
            PSTRING() << "parse account: " << parsed.error(), req_id_inner));
        return;
      }
      auto state_json = PSTRING() << td::JsonString(td::Slice(parsed.ok().state_str));
      promise_inner.set_value(make_json_ok(state_json, req_id_inner));
    }));
  };

  if (has_seqno) {
    // Step 1a: lookupBlock to resolve seqno to full block ID
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0),
        true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

    send_liteserver_query(std::move(lookup_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
            td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "lookupBlock: " << R.error(), req_id));
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
              R.move_as_ok(), true);
          if (lb_r.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_get_account(std::move(lb->id_), std::move(req_id), std::move(promise));
        });
  } else {
    // Step 1b: getMasterchainInfo to get latest block
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

    send_liteserver_query(std::move(mc_query),
        [req_id = std::move(req_id), promise = std::move(promise),
         do_get_account = std::move(do_get_account)](
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
          do_get_account(std::move(mc.ok()->last_), std::move(req_id), std::move(promise));
        });
  }
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

// ─── getLibraries ──────────────────────────────────────────────────────────

void JsonRpcServer::handle_getLibraries(td::JsonObject &params, std::string req_id,
                                        td::Promise<HttpReturn> promise) {
  // Parse library_list — a JSON array of base64-encoded 256-bit hashes
  auto list_val = params.extract_field("library_list");
  if (list_val.type() != td::JsonValue::Type::Array) {
    promise.set_value(make_json_error(-32602,
        "Missing or invalid 'library_list' (expected JSON array)", req_id));
    return;
  }
  auto &arr = list_val.get_array();
  std::vector<td::Bits256> hashes;
  hashes.reserve(arr.size());
  for (auto &elem : arr) {
    if (elem.type() != td::JsonValue::Type::String) {
      promise.set_value(make_json_error(-32602,
          "library_list entries must be base64 strings", req_id));
      return;
    }
    auto decoded_r = td::base64_decode(elem.get_string());
    if (decoded_r.is_error() || decoded_r.ok().size() != 32) {
      promise.set_value(make_json_error(-32602,
          "Invalid base64 hash in library_list (expected 32 bytes)", req_id));
      return;
    }
    td::Bits256 hash;
    hash.as_slice().copy_from(decoded_r.ok());
    hashes.push_back(hash);
  }

  if (hashes.empty()) {
    promise.set_value(make_json_ok(
        "{\"@type\":\"smc.libraryResult\",\"result\":[]}", req_id));
    return;
  }

  // Construct liteServer.getLibraries(library_list)
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getLibraries>(std::move(hashes)), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getLibraries failed: " << R.error(), req_id));
          return;
        }
        auto lib_r = tos::fetch_tl_object<tos::lite_api::liteServer_libraryResult>(
            R.move_as_ok(), true);
        if (lib_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse libraryResult: " << lib_r.error(), req_id));
          return;
        }
        auto lib = lib_r.move_as_ok();

        td::StringBuilder sb;
        sb << "{\"@type\":\"smc.libraryResult\",\"result\":[";
        for (size_t i = 0; i < lib->result_.size(); i++) {
          if (i > 0) sb << ",";
          auto &entry = lib->result_[i];
          auto hash_b64 = td::base64_encode(entry->hash_.as_slice());
          auto data_b64 = td::base64_encode(entry->data_.as_slice());
          sb << "{\"hash\":" << td::JsonString(td::Slice(hash_b64))
             << ",\"data\":" << td::JsonString(td::Slice(data_b64)) << "}";
        }
        sb << "]}";
        promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
      });
}

// ─── getTokenData ──────────────────────────────────────────────────────────
// Convenience method: tries get_jetton_data, falls back to get_nft_data.

void JsonRpcServer::handle_getTokenData(td::JsonObject &params, std::string req_id,
                                        td::Promise<HttpReturn> promise) {
  auto addr_r = parse_address_param(params);
  if (addr_r.is_error()) {
    promise.set_value(make_json_error(-32602, addr_r.error().message().str(), req_id));
    return;
  }
  auto addr = addr_r.move_as_ok();

  // Optional seqno parameter (query token data at a specific MC block)
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  // Serialize empty stack for runSmcMethod params
  vm::CellBuilder cb;
  vm::Stack empty_stack;
  if (!empty_stack.serialize(cb)) {
    promise.set_value(make_json_error(-32603, "stack serialize error", req_id));
    return;
  }
  auto params_boc_r = vm::std_boc_serialize(cb.finalize());
  if (params_boc_r.is_error()) {
    promise.set_value(make_json_error(-32603, "params BOC error", req_id));
    return;
  }
  auto params_boc = std::make_shared<td::BufferSlice>(params_boc_r.move_as_ok());

  // Step 2 lambda: given a resolved block, run get_jetton_data / get_nft_data
  auto do_query_token = [addr, params_boc, req_id = std::move(req_id),
                         self_id = actor_id(this), promise = std::move(promise)](
      td::int32 blk_wc, td::int64 blk_shard, td::int32 blk_seqno,
      td::Bits256 blk_root, td::Bits256 blk_file) mutable {

        auto saved_wc = blk_wc;
        auto saved_shard = blk_shard;
        auto saved_seqno = blk_seqno;
        auto saved_root = blk_root;
        auto saved_file = blk_file;

        // Step 2: try get_jetton_data
        td::int64 jetton_method_id = (td::crc16(td::Slice("get_jetton_data")) & 0xffff) | 0x10000;
        auto blk = tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(
            blk_wc, blk_shard, blk_seqno, blk_root, blk_file);
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                0x04, std::move(blk),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr),
                jetton_method_id, params_boc->clone()),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [addr, params_boc, self_id,
                 saved_wc, saved_shard, saved_seqno, saved_root, saved_file,
                 req_id = std::move(req_id), promise = std::move(promise)](
                    td::Result<td::BufferSlice> R) mutable {
          // Helper: parse address from a stack slice entry
          auto parse_address_from_slice = [](const vm::StackEntry& entry) -> std::string {
            if (entry.type() != vm::StackEntry::t_slice) return "";
            auto cs = entry.as_slice();
            if (cs->size() < 2) return "";
            auto tag = cs->prefetch_ulong(2);
            if (tag == 0) return "";      // addr_none
            if (tag != 2) return "";      // not addr_std
            vm::CellSlice tmp(*cs);
            tmp.advance(2);
            if (tmp.size() < 1) return "";
            auto has_anycast = tmp.fetch_ulong(1);
            if (has_anycast) {
              if (tmp.size() < 5) return "";
              auto depth = (int)tmp.fetch_ulong(5);
              tmp.advance(depth);
            }
            if (tmp.size() < 8 + 256) return "";
            auto workchain = (td::int8)tmp.fetch_long(8);
            td::Bits256 address;
            tmp.fetch_bits_to(address.bits(), 256);
            block::StdAddress a(workchain, address);
            a.bounceable = true;
            a.testnet = false;
            return a.rserialize(true);
          };

          // Helper: serialize a cell stack entry to base64 BOC
          auto cell_to_b64 = [](const vm::StackEntry& entry) -> std::string {
            if (!entry.is_cell()) return "";
            auto boc = vm::std_boc_serialize(entry.as_cell());
            if (boc.is_error()) return "";
            return td::base64_encode(boc.ok().as_slice());
          };

          // Try to parse jetton result
          if (R.is_ok()) {
            auto F = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
                R.move_as_ok(), true);
            if (F.is_ok()) {
              auto f = F.move_as_ok();
              if (f->exit_code_ == 0 && !f->result_.empty()) {
                auto cell_r = vm::std_boc_deserialize(f->result_.as_slice());
                if (cell_r.is_ok()) {
                  auto stk = td::make_ref<vm::Stack>();
                  auto result_cell = cell_r.move_as_ok();
                  vm::CellSlice cs = vm::load_cell_slice(result_cell);
                  if (stk.write().deserialize(cs) && stk->depth() >= 5) {
                    auto& total_supply_e = stk->at(0);
                    auto& mintable_e = stk->at(1);
                    auto& admin_addr_e = stk->at(2);
                    auto& content_e = stk->at(3);
                    auto& wallet_code_e = stk->at(4);

                    if (total_supply_e.is_int()) {
                      auto total_supply_str = total_supply_e.as_int()->to_dec_string();
                      bool mintable = mintable_e.is_int() && mintable_e.as_int()->to_long() != 0;
                      auto admin_addr_str = parse_address_from_slice(admin_addr_e);
                      auto content_b64 = cell_to_b64(content_e);
                      auto wallet_code_b64 = cell_to_b64(wallet_code_e);

                      td::StringBuilder sb;
                      sb << "{\"@type\":\"jetton.data\""
                         << ",\"total_supply\":" << td::JsonString(td::Slice(total_supply_str))
                         << ",\"mintable\":" << (mintable ? "true" : "false")
                         << ",\"admin_address\":" << td::JsonString(td::Slice(admin_addr_str))
                         << ",\"jetton_content\":" << td::JsonString(td::Slice(content_b64))
                         << ",\"jetton_wallet_code\":" << td::JsonString(td::Slice(wallet_code_b64))
                         << "}";
                      promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
                      return;
                    }
                  }
                }
              }
            }
          }

          // Jetton failed — try get_nft_data
          auto blk = tos::create_tl_object<tos::lite_api::tosNode_blockIdExt>(
              saved_wc, saved_shard, saved_seqno, saved_root, saved_file);
          td::int64 nft_method_id = (td::crc16(td::Slice("get_nft_data")) & 0xffff) | 0x10000;
          auto nft_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                  0x04, std::move(blk),
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      addr.workchain, addr.addr),
                  nft_method_id, params_boc->clone()),
              true);
          auto nft_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(nft_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(nft_query),
              td::PromiseCreator::lambda(
                  [req_id = std::move(req_id), promise = std::move(promise),
                   parse_address_from_slice, cell_to_b64](
                      td::Result<td::BufferSlice> R2) mutable {
            if (R2.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "getTokenData: both get_jetton_data and get_nft_data failed: "
                            << R2.error(), req_id));
              return;
            }
            auto F2 = tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
                R2.move_as_ok(), true);
            if (F2.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "parse NFT runMethodResult: " << F2.error(), req_id));
              return;
            }
            auto f2 = F2.move_as_ok();
            if (f2->exit_code_ != 0) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "getTokenData: contract is neither Jetton nor NFT (get_nft_data exit_code="
                            << f2->exit_code_ << ")", req_id));
              return;
            }
            if (f2->result_.empty()) {
              promise.set_value(make_json_error(-32603,
                  "getTokenData: get_nft_data returned empty result", req_id));
              return;
            }

            auto cell_r = vm::std_boc_deserialize(f2->result_.as_slice());
            if (cell_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  "getTokenData: failed to deserialize NFT result", req_id));
              return;
            }
            auto stk = td::make_ref<vm::Stack>();
            auto result_cell = cell_r.move_as_ok();
            vm::CellSlice cs = vm::load_cell_slice(result_cell);
            if (!stk.write().deserialize(cs) || stk->depth() < 5) {
              promise.set_value(make_json_error(-32603,
                  "getTokenData: get_nft_data returned fewer than 5 stack entries", req_id));
              return;
            }

            auto& init_e = stk->at(0);
            auto& index_e = stk->at(1);
            auto& collection_e = stk->at(2);
            auto& owner_e = stk->at(3);
            auto& content_e = stk->at(4);

            bool init_val = init_e.is_int() && init_e.as_int()->to_long() != 0;
            td::int64 index_val = index_e.is_int() ? index_e.as_int()->to_long() : 0;
            auto collection_str = parse_address_from_slice(collection_e);
            auto owner_str = parse_address_from_slice(owner_e);
            auto content_b64 = cell_to_b64(content_e);

            td::StringBuilder sb;
            sb << "{\"@type\":\"nft.data\""
               << ",\"init\":" << (init_val ? "true" : "false")
               << ",\"index\":" << index_val
               << ",\"collection_address\":" << td::JsonString(td::Slice(collection_str))
               << ",\"owner_address\":" << td::JsonString(td::Slice(owner_str))
               << ",\"individual_content\":" << td::JsonString(td::Slice(content_b64))
               << "}";
            promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
          }));
        }));
  };  // end of do_query_token lambda

  // Step 1: resolve block (by seqno or latest)
  auto self_id = actor_id(this);
  if (has_seqno) {
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0), true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    send_liteserver_query(std::move(lookup_query),
        [do_query_token = std::move(do_query_token)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            // Cannot proceed — just drop the promise (timeout will handle it)
            return;
          }
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) {
            return;
          }
          auto lb = lb_r.move_as_ok();
          do_query_token(lb->id_->workchain_, lb->id_->shard_, lb->id_->seqno_,
                         lb->id_->root_hash_, lb->id_->file_hash_);
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_query_token = std::move(do_query_token)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            return;
          }
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) {
            return;
          }
          auto mc = mc_r.move_as_ok();
          do_query_token(mc->last_->workchain_, mc->last_->shard_, mc->last_->seqno_,
                         mc->last_->root_hash_, mc->last_->file_hash_);
        });
  }
}

// ─── detectHash ──────────────────────────────────────────────────────────
// Pure utility method (no backend query). Accepts a hash in base64, base64url,
// or hex form, decodes it to raw bytes, and returns all three encodings.
// Aligned with ton-http-api-cpp DetectHashHandler / DetectHashResult.

static td::Result<std::string> decode_hash_input(const std::string& hash) {
  if (hash.empty()) {
    return td::Status::Error("empty hash");
  }
  // base64 (44 chars with padding)
  if (hash.length() == 44) {
    auto r = td::base64_decode(hash);
    if (r.is_ok()) return r.move_as_ok();
    auto r2 = td::base64url_decode(hash);
    if (r2.is_ok()) return r2.move_as_ok();
  }
  // base64url without padding (43 chars)
  if (hash.length() == 43) {
    auto r = td::base64url_decode(hash);
    if (r.is_ok()) return r.move_as_ok();
  }
  // hex (64 chars)
  if (hash.length() == 64) {
    auto r = td::hex_decode(td::Slice(hash));
    if (r.is_ok()) return r.move_as_ok();
  }
  return td::Status::Error(PSTRING() << "invalid hash: '" << hash << "'");
}

void JsonRpcServer::handle_detectHash(td::JsonObject &params, std::string req_id,
                                      td::Promise<HttpReturn> promise) {
  auto hash_str_r = params.get_required_string_field("hash");
  if (hash_str_r.is_error()) {
    promise.set_value(make_json_error(-32602, "Missing 'hash'", req_id));
    return;
  }
  auto hash_str = hash_str_r.move_as_ok();

  auto decoded_r = decode_hash_input(hash_str);
  if (decoded_r.is_error()) {
    promise.set_value(make_json_error(-32602, decoded_r.error().message().str(), req_id));
    return;
  }
  auto raw_bytes = decoded_r.move_as_ok();

  auto b64 = td::base64_encode(td::Slice(raw_bytes));
  auto b64url = td::base64url_encode(td::Slice(raw_bytes));
  auto hex = td::hex_encode(td::Slice(raw_bytes));

  td::StringBuilder sb;
  sb << "{\"@type\":\"ext.utils.detectedHash\""
     << ",\"b64\":" << td::JsonString(td::Slice(b64))
     << ",\"b64url\":" << td::JsonString(td::Slice(b64url))
     << ",\"hex\":" << td::JsonString(td::Slice(hex))
     << "}";
  promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
}

// ─── getOutMsgQueueSize ──────────────────────────────────────────────────
// Queries liteServer.getOutMsgQueueSizes (mode=0, no shard filter) and returns
// the per-shard queue sizes. The liteserver primitive is available in TOS.

void JsonRpcServer::handle_getOutMsgQueueSize(td::JsonObject &params, std::string req_id,
                                              td::Promise<HttpReturn> promise) {
  // mode=0 means no workchain/shard filter
  auto inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getOutMsgQueueSizes>(0, 0, 0), true);
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

  send_liteserver_query(std::move(query),
      [req_id = std::move(req_id), promise = std::move(promise)](
          td::Result<td::BufferSlice> R) mutable {
        if (R.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "getOutMsgQueueSizes: " << R.error(), req_id));
          return;
        }
        auto qs_r = tos::fetch_tl_object<tos::lite_api::liteServer_outMsgQueueSizes>(
            R.move_as_ok(), true);
        if (qs_r.is_error()) {
          promise.set_value(make_json_error(-32603,
              PSTRING() << "parse outMsgQueueSizes: " << qs_r.error(), req_id));
          return;
        }
        auto qs = qs_r.move_as_ok();

        td::StringBuilder sb;
        sb << "{\"@type\":\"blocks.outMsgQueueSizes\""
           << ",\"shards\":[";
        for (size_t i = 0; i < qs->shards_.size(); i++) {
          if (i > 0) sb << ",";
          auto& shard = qs->shards_[i];
          sb << "{\"@type\":\"blocks.outMsgQueueSize\""
             << ",\"id\":" << format_block_id_json(*shard->id_)
             << ",\"size\":" << shard->size_
             << "}";
        }
        sb << "]"
           << ",\"ext_msg_queue_size_limit\":" << qs->ext_msg_queue_size_limit_
           << "}";
        promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
      });
}

// ─── getConfigAll ────────────────────────────────────────────────────────
// Retrieves the full blockchain configuration (all config params).
// Uses liteServer.getConfigAll which is a distinct TL method from getConfigParams.
// Accepts optional "seqno" parameter to query config at a specific mc block.

void JsonRpcServer::handle_getConfigAll(td::JsonObject &params, std::string req_id,
                                        td::Promise<HttpReturn> promise) {
  // Optional seqno parameter — if provided, we look up that specific block
  td::int32 seqno = 0;
  auto seqno_r = params.get_optional_int_field("seqno");
  if (seqno_r.is_ok() && seqno_r.ok() > 0) {
    seqno = static_cast<td::int32>(seqno_r.ok());
  }

  // Step 1: Get masterchain info (or lookup specific block by seqno)
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [seqno, req_id = std::move(req_id), self_id, promise = std::move(promise)](
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

        // If specific seqno requested, look up that block first
        if (seqno > 0) {
          auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
              -1, static_cast<td::int64>(-1LL << 63), seqno);
          auto lookup_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
                  1, std::move(block_id), 0, 0),
              true);
          auto lookup_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(lookup_query),
              td::PromiseCreator::lambda(
                  [req_id = std::move(req_id), self_id, promise = std::move(promise)](
                      td::Result<td::BufferSlice> R) mutable {
            if (R.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "lookupBlock: " << R.error(), req_id));
              return;
            }
            auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(
                R.move_as_ok(), true);
            if (lb_r.is_error()) {
              promise.set_value(make_json_error(-32603,
                  PSTRING() << "parse lookupBlock: " << lb_r.error(), req_id));
              return;
            }
            auto lb = lb_r.move_as_ok();

            // Step 2: getConfigAll with the resolved block ID
            auto inner = tos::serialize_tl_object(
                tos::create_tl_object<tos::lite_api::liteServer_getConfigAll>(
                    0, std::move(lb->id_)),
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
                    PSTRING() << "getConfigAll failed: " << R.error(), req_id));
                return;
              }
              auto F = tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(
                  R.move_as_ok(), true);
              if (F.is_error()) {
                promise.set_value(make_json_error(-32603,
                    PSTRING() << "parse configInfo: " << F.error(), req_id));
                return;
              }
              auto f = F.move_as_ok();

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

              // Serialize all config params as an object mapping param_id -> base64 BOC
              td::StringBuilder sb;
              sb << "{\"@type\":\"configInfo\""
                 << ",\"config\":{\"@type\":\"tvm.cell\"";
              // Serialize the full config cell as a BOC
              auto config_root = cfg->get_root_cell();
              if (config_root.not_null()) {
                auto boc_r = vm::std_boc_serialize(config_root);
                if (boc_r.is_ok()) {
                  sb << ",\"bytes\":" << td::JsonString(td::Slice(td::base64_encode(boc_r.ok().as_slice())));
                }
              }
              sb << "}";

              // Also include individual config params for convenience
              sb << ",\"config_params\":{";
              bool first_param = true;
              cfg->foreach_config_param([&](int id, td::Ref<vm::Cell> cell) -> bool {
                if (!first_param) sb << ",";
                first_param = false;
                auto boc_r = vm::std_boc_serialize(cell);
                if (boc_r.is_ok()) {
                  sb << "\"" << id << "\":{\"bytes\":"
                     << td::JsonString(td::Slice(td::base64_encode(boc_r.ok().as_slice())))
                     << "}";
                } else {
                  sb << "\"" << id << "\":null";
                }
                return true;
              });
              sb << "}}";
              promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
            }));
          }));
          return;
        }

        // No seqno — use latest masterchain block
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getConfigAll>(
                0, std::move(mc->last_)),
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
                PSTRING() << "getConfigAll failed: " << R.error(), req_id));
            return;
          }
          auto F = tos::fetch_tl_object<tos::lite_api::liteServer_configInfo>(
              R.move_as_ok(), true);
          if (F.is_error()) {
            promise.set_value(make_json_error(-32603,
                PSTRING() << "parse configInfo: " << F.error(), req_id));
            return;
          }
          auto f = F.move_as_ok();

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

          td::StringBuilder sb;
          sb << "{\"@type\":\"configInfo\""
             << ",\"config\":{\"@type\":\"tvm.cell\"";
          auto config_root = cfg->get_root_cell();
          if (config_root.not_null()) {
            auto boc_r = vm::std_boc_serialize(config_root);
            if (boc_r.is_ok()) {
              sb << ",\"bytes\":" << td::JsonString(td::Slice(td::base64_encode(boc_r.ok().as_slice())));
            }
          }
          sb << "}";

          sb << ",\"config_params\":{";
          bool first_param = true;
          cfg->foreach_config_param([&](int id, td::Ref<vm::Cell> cell) -> bool {
            if (!first_param) sb << ",";
            first_param = false;
            auto boc_r = vm::std_boc_serialize(cell);
            if (boc_r.is_ok()) {
              sb << "\"" << id << "\":{\"bytes\":"
                 << td::JsonString(td::Slice(td::base64_encode(boc_r.ok().as_slice())))
                 << "}";
            } else {
              sb << "\"" << id << "\":null";
            }
            return true;
          });
          sb << "}}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
        }));
      });
}

// ─── getTransactionsStd ──────────────────────────────────────────────────
// Standardized version of getTransactions. Same parameters as getTransactions
// but lt and hash are optional (auto-fetched from account state if omitted).
// Returns raw transaction BOCs in the same shape as the reference
// ton-http-api-cpp TransactionsStd response.

void JsonRpcServer::handle_getTransactionsStd(td::JsonObject &params, std::string req_id,
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

  // lt and hash are optional for the Std variant
  td::int64 lt = 0;
  td::Bits256 hash = td::Bits256::zero();
  bool has_lt = false;
  bool has_hash = false;

  auto lt_r = params.get_optional_string_field("lt");
  if (lt_r.is_ok() && !lt_r.ok().empty()) {
    lt = std::strtoll(lt_r.ok().c_str(), nullptr, 10);
    has_lt = true;
  }

  auto hash_r = params.get_optional_string_field("hash");
  if (hash_r.is_ok() && !hash_r.ok().empty()) {
    auto hash_decoded = td::base64_decode(hash_r.ok());
    if (hash_decoded.is_ok() && hash_decoded.ok().size() == 32) {
      hash.as_slice().copy_from(hash_decoded.ok());
      has_hash = true;
    } else {
      auto hex_r = td::hex_decode(td::Slice(hash_r.ok()));
      if (hex_r.is_ok() && hex_r.ok().size() == 32) {
        hash.as_slice().copy_from(hex_r.ok());
        has_hash = true;
      }
    }
  }

  // Validate: lt and hash must be used together if provided
  if (has_lt != has_hash) {
    promise.set_value(make_json_error(-32602, "lt and hash should be used together", req_id));
    return;
  }

  // If lt/hash are provided, go directly to getTransactions
  if (has_lt && has_hash) {
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

          td::StringBuilder sb;
          sb << "{\"@type\":\"raw.transactions\""
             << ",\"transactions\":[";

          // Track the last lt/hash for previous_transaction_id
          td::uint64 prev_lt = 0;
          std::string prev_hash_b64;

          if (!tl->transactions_.empty()) {
            auto root_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
            if (root_r.is_ok()) {
              auto roots = root_r.move_as_ok();
              for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
                if (i > 0) sb << ",";
                sb << "{\"@type\":\"raw.transaction\"";

                block::gen::Transaction::Record tx;
                if (tlb::unpack_cell(roots[i], tx)) {
                  sb << ",\"utime\":" << tx.now;
                  auto tx_hash = roots[i]->get_hash(0);
                  sb << ",\"data\":\"" << td::base64_encode(
                      vm::std_boc_serialize(roots[i]).move_as_ok().as_slice()) << "\"";
                  sb << ",\"transaction_id\":{\"@type\":\"internal.transactionId\""
                     << ",\"lt\":\"" << tx.lt << "\""
                     << ",\"hash\":\"" << td::base64_encode(tx_hash.as_slice()) << "\"}";

                  // Track previous transaction from last entry
                  if (i == roots.size() - 1 || i == tl->ids_.size() - 1) {
                    prev_lt = tx.prev_trans_lt;
                    prev_hash_b64 = td::base64_encode(tx.prev_trans_hash.as_slice());
                  }
                }
                sb << "}";
              }
            }
          }

          sb << "]"
             << ",\"previous_transaction_id\":{\"@type\":\"internal.transactionId\""
             << ",\"lt\":\"" << prev_lt << "\""
             << ",\"hash\":\"" << prev_hash_b64 << "\"}"
             << "}";
          promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
        });
    return;
  }

  // No lt/hash provided: first get account state to find last_trans_lt/hash
  auto mc_inner = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
  auto mc_query = tos::serialize_tl_object(
      tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);

  auto self_id = actor_id(this);
  send_liteserver_query(std::move(mc_query),
      [addr, limit, req_id = std::move(req_id), self_id,
       promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
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

        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_getAccountState>(
                std::move(mc->last_),
                tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                    addr.workchain, addr.addr)),
            true);
        auto query = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(inner)), true);

        td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
            std::move(query),
            td::PromiseCreator::lambda(
                [addr, limit, req_id = std::move(req_id), self_id,
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
          auto ps = parsed.move_as_ok();

          if (ps.last_trans_lt == 0) {
            // No transactions on this account
            promise.set_value(make_json_ok(
                "{\"@type\":\"raw.transactions\",\"transactions\":[]"
                ",\"previous_transaction_id\":{\"@type\":\"internal.transactionId\""
                ",\"lt\":\"0\",\"hash\":\"\"}}",
                req_id));
            return;
          }

          // Decode last_trans_hash from base64
          td::Bits256 last_hash;
          auto hash_dec = td::base64_decode(ps.last_trans_hash_b64);
          if (hash_dec.is_ok() && hash_dec.ok().size() == 32) {
            last_hash.as_slice().copy_from(hash_dec.ok());
          }

          auto tx_inner = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_getTransactions>(
                  limit,
                  tos::create_tl_object<tos::lite_api::liteServer_accountId>(
                      addr.workchain, addr.addr),
                  static_cast<td::int64>(ps.last_trans_lt), last_hash),
              true);
          auto tx_query = tos::serialize_tl_object(
              tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(tx_inner)), true);

          td::actor::send_closure(self_id, &JsonRpcServer::send_liteserver_query,
              std::move(tx_query),
              td::PromiseCreator::lambda(
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

            td::StringBuilder sb;
            sb << "{\"@type\":\"raw.transactions\""
               << ",\"transactions\":[";

            td::uint64 prev_lt = 0;
            std::string prev_hash_b64;

            if (!tl->transactions_.empty()) {
              auto root_r = vm::std_boc_deserialize_multi(tl->transactions_.as_slice());
              if (root_r.is_ok()) {
                auto roots = root_r.move_as_ok();
                for (size_t i = 0; i < roots.size() && i < tl->ids_.size(); i++) {
                  if (i > 0) sb << ",";
                  sb << "{\"@type\":\"raw.transaction\"";

                  block::gen::Transaction::Record tx;
                  if (tlb::unpack_cell(roots[i], tx)) {
                    sb << ",\"utime\":" << tx.now;
                    auto tx_hash = roots[i]->get_hash(0);
                    auto boc_r = vm::std_boc_serialize(roots[i]);
                    if (boc_r.is_ok()) {
                      sb << ",\"data\":\"" << td::base64_encode(boc_r.ok().as_slice()) << "\"";
                    }
                    sb << ",\"transaction_id\":{\"@type\":\"internal.transactionId\""
                       << ",\"lt\":\"" << tx.lt << "\""
                       << ",\"hash\":\"" << td::base64_encode(tx_hash.as_slice()) << "\"}";

                    if (i == roots.size() - 1 || i == tl->ids_.size() - 1) {
                      prev_lt = tx.prev_trans_lt;
                      prev_hash_b64 = td::base64_encode(tx.prev_trans_hash.as_slice());
                    }
                  }
                  sb << "}";
                }
              }
            }

            sb << "]"
               << ",\"previous_transaction_id\":{\"@type\":\"internal.transactionId\""
               << ",\"lt\":\"" << prev_lt << "\""
               << ",\"hash\":\"" << prev_hash_b64 << "\"}"
               << "}";
            promise.set_value(make_json_ok(sb.as_cslice().str(), req_id));
          }));
        }));
      });
}

// ─── runGetMethodStd ─────────────────────────────────────────────────────
// Standardized version of runGetMethod. Same parameters (address, method, stack)
// but returns results in the TVM stack entry format with typed entries
// (tvm.stackEntryNumber, tvm.stackEntryCell, tvm.stackEntrySlice, etc.)
// rather than the legacy ["num", "value"] array format.

void JsonRpcServer::handle_runGetMethodStd(td::JsonObject &params, std::string req_id,
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

  // Parse optional stack parameter (array of ["type", "value"] pairs)
  vm::Stack stack;
  auto stack_r = params.extract_field("stack");
  if (stack_r.type() == td::JsonValue::Type::Array) {
    auto& arr = stack_r.get_array();
    for (auto& entry : arr) {
      if (entry.type() != td::JsonValue::Type::Array) continue;
      auto& pair = entry.get_array();
      if (pair.size() < 2) continue;
      if (pair[0].type() != td::JsonValue::Type::String) continue;
      auto type_str = pair[0].get_string().str();
      if (type_str == "num" || type_str == "tvm.Number") {
        std::string val_str;
        if (pair[1].type() == td::JsonValue::Type::String) {
          val_str = pair[1].get_string().str();
        } else if (pair[1].type() == td::JsonValue::Type::Number) {
          val_str = pair[1].get_number().str();
        } else {
          continue;
        }
        auto num = td::string_to_int256(val_str);
        if (num.not_null()) {
          stack.push(vm::StackEntry(std::move(num)));
        }
      } else if (type_str == "cell" || type_str == "tvm.Cell") {
        std::string b64;
        if (pair[1].type() == td::JsonValue::Type::Object) {
          auto bytes_r = pair[1].get_object().get_required_string_field("bytes");
          if (bytes_r.is_ok()) b64 = bytes_r.ok();
        } else if (pair[1].type() == td::JsonValue::Type::String) {
          b64 = pair[1].get_string().str();
        }
        if (!b64.empty()) {
          auto decoded = td::base64_decode(b64);
          if (decoded.is_ok()) {
            auto cell = vm::std_boc_deserialize(td::Slice(decoded.ok()));
            if (cell.is_ok()) {
              stack.push(vm::StackEntry(cell.move_as_ok()));
            }
          }
        }
      } else if (type_str == "slice" || type_str == "tvm.Slice") {
        std::string b64;
        if (pair[1].type() == td::JsonValue::Type::Object) {
          auto bytes_r = pair[1].get_object().get_required_string_field("bytes");
          if (bytes_r.is_ok()) b64 = bytes_r.ok();
        } else if (pair[1].type() == td::JsonValue::Type::String) {
          b64 = pair[1].get_string().str();
        }
        if (!b64.empty()) {
          auto decoded = td::base64_decode(b64);
          if (decoded.is_ok()) {
            auto cell = vm::std_boc_deserialize(td::Slice(decoded.ok()));
            if (cell.is_ok()) {
              stack.push(vm::StackEntry(vm::load_cell_slice_ref(cell.move_as_ok())));
            }
          }
        }
      }
    }
  }

  // Serialize stack as params
  vm::CellBuilder cb;
  if (!stack.serialize(cb)) {
    promise.set_value(make_json_error(-32603, "stack serialize error", req_id));
    return;
  }
  auto params_boc_r = vm::std_boc_serialize(cb.finalize());
  if (params_boc_r.is_error()) {
    promise.set_value(make_json_error(-32603, "params BOC error", req_id));
    return;
  }

  // Optional seqno: query at a specific MC block
  auto seqno_r = params.get_optional_int_field("seqno");
  bool has_seqno = seqno_r.is_ok() && seqno_r.ok() > 0;
  td::int32 seqno = has_seqno ? static_cast<td::int32>(seqno_r.ok()) : 0;

  auto params_boc = params_boc_r.move_as_ok();

  // Step 2 lambda: runSmcMethod at a resolved block
  auto do_run_method = [addr, method_id, params_boc = std::move(params_boc),
                        req_id = std::move(req_id), self_id = actor_id(this),
                        promise = std::move(promise)](
      tos::tl_object_ptr<tos::lite_api::tosNode_blockIdExt> block_id) mutable {
        auto inner = tos::serialize_tl_object(
            tos::create_tl_object<tos::lite_api::liteServer_runSmcMethod>(
                0x04, std::move(block_id),
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

          // Parse result stack into standardized typed format
          std::string stack_json = "[]";
          if (!f->result_.empty()) {
            auto cell_r = vm::std_boc_deserialize(f->result_.as_slice());
            if (cell_r.is_ok()) {
              auto stk = td::make_ref<vm::Stack>();
              auto result_cell = cell_r.move_as_ok();
              vm::CellSlice cs = vm::load_cell_slice(result_cell);
              if (stk.write().deserialize(cs)) {
                // Convert stack to standardized TVM stack entries
                td::StringBuilder sb;
                sb << "[";
                for (int i = 0; i < (int)stk->depth(); i++) {
                  if (i > 0) sb << ",";
                  auto& entry = stk->at(i);
                  if (entry.is_int()) {
                    auto val = entry.as_int();
                    sb << "{\"@type\":\"tvm.stackEntryNumber\""
                       << ",\"number\":{\"@type\":\"tvm.numberDecimal\""
                       << ",\"number\":" << td::JsonString(td::Slice(val->to_dec_string()))
                       << "}}";
                  } else if (entry.is_cell()) {
                    auto boc = vm::std_boc_serialize(entry.as_cell());
                    if (boc.is_ok()) {
                      sb << "{\"@type\":\"tvm.stackEntryCell\""
                         << ",\"cell\":{\"@type\":\"tvm.cell\""
                         << ",\"bytes\":" << td::JsonString(td::Slice(
                                td::base64_encode(boc.ok().as_slice())))
                         << "}}";
                    } else {
                      sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
                    }
                  } else if (entry.type() == vm::StackEntry::t_slice) {
                    // Serialize slice as a cell for portability
                    vm::CellBuilder cb2;
                    auto slice = entry.as_slice();
                    if (cb2.append_cellslice_bool(slice)) {
                      auto boc = vm::std_boc_serialize(cb2.finalize());
                      if (boc.is_ok()) {
                        sb << "{\"@type\":\"tvm.stackEntrySlice\""
                           << ",\"slice\":{\"@type\":\"tvm.slice\""
                           << ",\"bytes\":" << td::JsonString(td::Slice(
                                  td::base64_encode(boc.ok().as_slice())))
                           << "}}";
                      } else {
                        sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
                      }
                    } else {
                      sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
                    }
                  } else {
                    sb << "{\"@type\":\"tvm.stackEntryUnsupported\"}";
                  }
                }
                sb << "]";
                stack_json = sb.as_cslice().str();
              }
            }
          }

          // Note: liteServer.runMethodResult does not include gas_used;
          // report 0 for compatibility (same as existing runGetMethod handler).
          auto result = PSTRING()
              << "{\"@type\":\"smc.runResult\""
              << ",\"gas_used\":0"
              << ",\"stack\":" << stack_json
              << ",\"exit_code\":" << f->exit_code_
              << "}";

          promise.set_value(make_json_ok(result, req_id));
        }));
  };  // end of do_run_method

  // Step 1: resolve block
  if (has_seqno) {
    auto block_id = tos::create_tl_object<tos::lite_api::tosNode_blockId>(
        -1, static_cast<td::int64>(-1LL << 63), seqno);
    auto lookup_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_lookupBlock>(
            1, std::move(block_id), 0, 0), true);
    auto lookup_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(lookup_inner)), true);
    send_liteserver_query(std::move(lookup_query),
        [do_run_method = std::move(do_run_method)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto lb_r = tos::fetch_tl_object<tos::lite_api::liteServer_blockHeader>(R.move_as_ok(), true);
          if (lb_r.is_error()) return;
          do_run_method(std::move(lb_r.move_as_ok()->id_));
        });
  } else {
    auto mc_inner = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_getMasterchainInfo>(), true);
    auto mc_query = tos::serialize_tl_object(
        tos::create_tl_object<tos::lite_api::liteServer_query>(std::move(mc_inner)), true);
    send_liteserver_query(std::move(mc_query),
        [do_run_method = std::move(do_run_method)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) return;
          auto mc_r = tos::fetch_tl_object<tos::lite_api::liteServer_masterchainInfo>(R.move_as_ok(), true);
          if (mc_r.is_error()) return;
          do_run_method(std::move(mc_r.move_as_ok()->last_));
        });
  }
}

// ─── sendBocReturnHashNoError ────────────────────────────────────────────
// Same as sendBocReturnHash but with "ignore errors" semantics.
// If the liteserver send fails, instead of returning the raw liteserver error,
// this method returns a structured error with code -32600 (keeping the original
// error message). This matches the ton-http-api-cpp behavior where
// ignore_errors=true normalizes error handling for fire-and-forget use cases.
// The hash is still computed and included even on failure.

void JsonRpcServer::handle_sendBocReturnHashNoError(td::JsonObject &params, std::string req_id,
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
          // NoError semantics: normalize errors to code -32600 with the
          // original error message. The hash is still returned in the
          // error message so clients can track the message.
          promise.set_value(make_json_error(-32600,
              PSTRING() << "sendBoc failed: " << R.error(), req_id));
          return;
        }
        auto data = R.move_as_ok();
        auto status_r = tos::fetch_tl_object<tos::lite_api::liteServer_sendMsgStatus>(
            std::move(data), true);
        if (status_r.is_error()) {
          // Even parse failures are normalized for NoError
          promise.set_value(make_json_error(-32600,
              PSTRING() << "sendBoc parse error: " << status_r.error(), req_id));
          return;
        }
        auto status = status_r.move_as_ok();
        promise.set_value(make_json_ok(
            PSTRING() << "{\"@type\":\"raw.extMessageInfo\""
                      << ",\"hash\":" << td::JsonString(td::Slice(msg_hash_b64)) << "}",
            req_id));
      });
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
  promise = td::PromiseCreator::lambda(
      [promise = std::move(promise)](td::Result<td::BufferSlice> result) mutable {
        if (result.is_error()) {
          promise.set_error(result.move_as_error());
          return;
        }
        auto data = result.move_as_ok();
        auto err_r = tos::fetch_tl_object<tos::lite_api::liteServer_error>(data.clone(), true);
        if (err_r.is_ok()) {
          auto err = err_r.move_as_ok();
          promise.set_error(td::Status::Error(err->code_, err->message_));
          return;
        }
        promise.set_value(std::move(data));
      });
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

JsonRpcServer::HttpReturn JsonRpcServer::make_json_unauthorized(const std::string& cors_origin) {
  std::string body =
      "{\"ok\":false,\"jsonrpc\":\"2.0\",\"id\":null,"
      "\"error\":\"Unauthorized: invalid or missing API key\",\"code\":-32000}";

  auto response = http::HttpResponse::create("HTTP/1.1", 401, "Unauthorized",
                                             false, false).move_as_ok();
  response->add_header({"Content-Type", "application/json"});
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice(body));
  payload->complete_parse();

  return {std::move(response), std::move(payload)};
}

// ─── API key check ──────────────────────────────────────────────────────

bool JsonRpcServer::check_api_key(const RequestPtr &request,
                                  td::Promise<HttpReturn> &promise) {
  if (opts_.api_key.empty()) {
    return true;  // no auth configured
  }

  // Check X-API-Key header
  auto key_header = request->get_header("X-API-Key");
  if (!key_header.empty() && key_header == opts_.api_key) {
    return true;
  }

  // Check api_key query parameter in URL
  auto url = request->url();
  auto qpos = url.find('?');
  if (qpos != std::string::npos) {
    std::string qs = url.substr(qpos + 1);
    size_t pos = 0;
    while (pos < qs.size()) {
      auto amp = qs.find('&', pos);
      auto token = qs.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
      pos = amp == std::string::npos ? qs.size() : amp + 1;
      if (token.empty()) continue;
      auto eq = token.find('=');
      if (eq != std::string::npos) {
        auto key = token.substr(0, eq);
        auto val = token.substr(eq + 1);
        if (key == "api_key" && val == opts_.api_key) {
          return true;
        }
      }
    }
  }

  // Auth failed
  promise.set_value(make_json_unauthorized(opts_.cors_origin));
  return false;
}

// ─── Response cache ─────────────────────────────────────────────────────

const std::set<std::string> &JsonRpcServer::cacheable_methods() {
  static const std::set<std::string> methods = {
      "getMasterchainInfo", "getConfigParam", "getConfigAll",
      "getAddressInformation", "getWalletInformation", "getAddressBalance",
      "getAddressState", "getBlockHeader", "lookupBlock", "shards",
      "getConsensusBlock", "getOutMsgQueueSize"
  };
  return methods;
}

void JsonRpcServer::alarm() {
  // Periodic cache cleanup — remove expired entries
  if (opts_.cache_ttl > 0 && !cache_.empty()) {
    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->second.expires_at.is_in_past()) {
        it = cache_.erase(it);
      } else {
        ++it;
      }
    }
  }
  // Re-arm alarm every 10 seconds if caching is enabled
  if (opts_.cache_ttl > 0) {
    alarm_timestamp() = td::Timestamp::in(10.0);
  }
}

void JsonRpcServer::cached_dispatch_method(std::string method, td::JsonObject &params,
                                           std::string req_id,
                                           td::Promise<HttpReturn> promise) {
  bool is_cacheable = opts_.cache_ttl > 0 && cacheable_methods().count(method);

  if (!is_cacheable) {
    dispatch_method(std::move(method), params, std::move(req_id), std::move(promise));
    return;
  }

  // Build cache key: method|field1=val1&field2=val2 (sorted by name)
  td::StringBuilder sb;
  sb << method << "|";
  // params.field_values_ is public — iterate and serialize
  std::vector<std::pair<std::string, std::string>> kvs;
  kvs.reserve(params.field_values_.size());
  for (auto &fv : params.field_values_) {
    // Use field name and a simple string representation of the value
    std::string val;
    switch (fv.second.type()) {
      case td::JsonValue::Type::String:
        val = fv.second.get_string().str();
        break;
      case td::JsonValue::Type::Number:
        val = fv.second.get_number().str();
        break;
      case td::JsonValue::Type::Boolean:
        val = fv.second.get_boolean() ? "true" : "false";
        break;
      case td::JsonValue::Type::Null:
        val = "null";
        break;
      default:
        val = "?";
        break;
    }
    kvs.emplace_back(fv.first.str(), std::move(val));
  }
  std::sort(kvs.begin(), kvs.end());
  for (size_t i = 0; i < kvs.size(); i++) {
    if (i > 0) sb << "&";
    sb << kvs[i].first << "=" << kvs[i].second;
  }
  std::string cache_key = sb.as_cslice().str();

  // Check cache
  auto it = cache_.find(cache_key);
  if (it != cache_.end() && !it->second.expires_at.is_in_past()) {
    // Cache hit — return cached response with the current request's id
    promise.set_value(make_json_ok(it->second.response_json, req_id));
    return;
  }

  // Cache miss — dispatch normally but wrap the promise to capture the result
  auto ttl = opts_.cache_ttl;
  auto cors = opts_.cors_origin;
  auto cache_promise = td::PromiseCreator::lambda(
      [this, cache_key = std::move(cache_key), ttl, req_id,
       cors, orig_promise = std::move(promise)](td::Result<HttpReturn> R) mutable {
        if (R.is_error()) {
          orig_promise.set_error(R.move_as_error());
          return;
        }
        auto result = R.move_as_ok();
        // Only cache successful (200) responses with "ok":true in the body
        if (result.first && result.first->code() == 200 && result.second) {
          // Read the payload body for inspection.  get_slice() consumes it,
          // so we must rebuild the response pair afterward.
          auto body_slice = result.second->get_slice(1 << 20);
          std::string body_str = body_slice.as_slice().str();

          if (body_str.find("\"ok\":true") != std::string::npos) {
            // Extract the "result" JSON value from the body.
            // Body format: {"ok":true,"jsonrpc":"2.0","id":...,"result":...}
            auto result_pos = body_str.find("\"result\":");
            if (result_pos != std::string::npos) {
              std::string result_json = body_str.substr(result_pos + 9);
              // Remove the trailing }
              if (!result_json.empty() && result_json.back() == '}') {
                result_json.pop_back();
              }
              cache_[cache_key] = CacheEntry{std::move(result_json),
                                             td::Timestamp::in(static_cast<double>(ttl))};
              orig_promise.set_value(make_json_ok(cache_[cache_key].response_json,
                                                  req_id, cors));
              return;
            }
          }
          // Could not extract result or not ok — rebuild and forward without caching
          auto resp = http::HttpResponse::create("HTTP/1.1", 200, "OK",
                                                 false, false).move_as_ok();
          resp->add_header({"Content-Type", "application/json"});
          resp->add_header({"Access-Control-Allow-Origin", cors});
          resp->add_header({"Transfer-Encoding", "Chunked"});
          resp->complete_parse_header();
          auto pl = resp->create_empty_payload().move_as_ok();
          pl->add_chunk(td::BufferSlice(body_str));
          pl->complete_parse();
          orig_promise.set_value({std::move(resp), std::move(pl)});
          return;
        }
        // Non-200 or error — forward as-is, don't cache
        orig_promise.set_value(std::move(result));
      });

  dispatch_method(std::move(method), params, std::move(req_id), std::move(cache_promise));
}

}  // namespace tos
