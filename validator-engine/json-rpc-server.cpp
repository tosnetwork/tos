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

#include "evm/rpc/handlers.h"
#include "uno/rpc/handlers.h"

#include <cstring>

namespace tos {

// ─── HTTP body draining helper ─────────────────────────────────────────────
//
// HttpPayload stores received bytes in a deque of fixed-size 16 KiB chunks.
// `HttpPayload::get_slice(max)` returns AT MOST ONE chunk per call, so a
// single call can return only the first 16 KiB of a larger body.  A request
// body of, say, 21 KiB would arrive split across two chunks: the first
// `get_slice` returns ~16 KiB, leaving the rest in the payload — which then
// gets dropped on the floor and the JSON parser sees a truncated body and
// rejects it with `-32700 invalid JSON` (HTTP 400).
//
// This helper drains the entire payload by repeatedly calling get_slice
// until either the payload is exhausted or the cap is hit.  Bodies larger
// than `max_body_bytes` are rejected up-front to prevent memory-exhaustion
// DoS.  See test/conformance/manual-rpc/http_large_request_body.io for the
// regression test that pins this behaviour.
//
// Cap: 1 MiB — comfortably accommodates complex `eth_simulateV1` and
// `eth_call` requests with many state overrides (Geth defaults to 5 MiB,
// Erigon to 1 MiB).
static constexpr std::size_t kJsonRpcMaxRequestBodyBytes = 1u << 20;

// Drain the entire payload into a single contiguous buffer.  Returns an
// error status if the body would exceed `kJsonRpcMaxRequestBodyBytes`
// (callers translate this to a -32600 "Request body too large" response so
// the client gets a deterministic rejection rather than a connection drop).
// Returns an empty BufferSlice for an empty body.
static td::Result<td::BufferSlice> drain_payload_body(
    const std::shared_ptr<http::HttpPayload> &payload) {
  // Fast path: single chunk fits in one get_slice call.
  auto first = payload->get_slice(kJsonRpcMaxRequestBodyBytes);
  if (first.empty()) {
    return td::BufferSlice{};
  }
  // See if there's more — peek by trying another get_slice.  In the common
  // (small body) case, the second call returns empty and we're done with
  // zero copying overhead.
  auto next = payload->get_slice(kJsonRpcMaxRequestBodyBytes);
  if (next.empty()) {
    return std::move(first);
  }
  // Multi-chunk path: concatenate all chunks into one BufferSlice.  This
  // copies the body once, but only triggers for bodies > 16 KiB which are
  // rare on a JSON-RPC server (typical request: a few hundred bytes).
  std::size_t total = first.size() + next.size();
  if (total > kJsonRpcMaxRequestBodyBytes) {
    return td::Status::Error("request body exceeds size limit");
  }
  std::vector<td::BufferSlice> parts;
  parts.reserve(4);
  parts.push_back(std::move(first));
  parts.push_back(std::move(next));
  while (true) {
    auto more = payload->get_slice(kJsonRpcMaxRequestBodyBytes);
    if (more.empty()) break;
    total += more.size();
    if (total > kJsonRpcMaxRequestBodyBytes) {
      return td::Status::Error("request body exceeds size limit");
    }
    parts.push_back(std::move(more));
  }
  td::BufferSlice combined{total};
  std::size_t off = 0;
  for (auto &p : parts) {
    std::memcpy(combined.data() + off, p.data(), p.size());
    off += p.size();
  }
  return std::move(combined);
}

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

// Strip api_key from query string before passing to handler/cache
static std::string strip_api_key_param(const std::string &qs) {
  std::string result;
  size_t pos = 0;
  while (pos < qs.size()) {
    auto amp = qs.find('&', pos);
    auto token = qs.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
    pos = amp == std::string::npos ? qs.size() : amp + 1;
    if (token.empty()) continue;
    auto eq = token.find('=');
    auto key = eq == std::string::npos ? token : token.substr(0, eq);
    if (key == "api_key") continue;  // skip
    if (!result.empty()) result += '&';
    result += token;
  }
  return result;
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
//
// NOTE: This guard wraps individual liteserver queries.  Handlers that
// chain N sequential queries can take up to N × timeout_seconds total
// wall-clock time.  A request-level timeout should be added at the
// dispatch layer for defense-in-depth against slow-loris-style attacks
// on multi-query handlers (e.g., getAccountAgents chains up to 6 queries).

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
    : validator_manager_(std::move(validator_manager)),
      opts_(std::move(options)),
      cache_(opts_.cache_max_entries, opts_.cache_max_body_bytes) {
  // Arm periodic cache cleanup if caching is enabled
  if (opts_.cache_ttl > 0) {
    alarm_timestamp() = td::Timestamp::in(10.0);
  }
}

void JsonRpcServer::listen(td::IPAddress addr) {
  CHECK(http_.empty());
  // Enable EVM RPC rate limiting for the production server
  evm_workchain::enable_evm_rpc_rate_limit(true);
  // Enable UNO RPC rate limiting (gate on uno_sendTransfer +
  // uno_sendMineUno). Without this, the per-method rate-limit checks in
  // uno_sendMineUno (forged-PI DoS hardening, K-mine-rate-limit) and
  // uno_sendTransfer are inert — `try_consume_uno_sendtx_token` returns
  // true on every call when g_rate_limit_enabled is false.
  uno_workchain::enable_uno_rpc_rate_limit(true);
  auto callback = std::make_shared<HttpCallback>(actor_id(this));
  http_ = td::actor::create_actor<http::HttpServer>(
      PSTRING() << "JsonRPC@" << addr, addr, std::move(callback));
  LOG(WARNING) << "JSON-RPC server listening on " << addr;

  // Codex audit (round 1, finding #2): refuse to silently expose a write-
  // enabled, unauthenticated RPC surface on a non-loopback address. Operators
  // who really want this must pass `--json-rpc-readonly` or `--json-rpc-api-key`.
  // We deliberately do NOT change the historical defaults (readonly=false,
  // empty api_key, cors=*) here — only loudly refuse the dangerous combination.
  bool is_loopback = false;
  {
    auto ip_str = addr.get_ip_str().str();
    if (ip_str == "127.0.0.1" || ip_str == "::1" || ip_str == "0:0:0:0:0:0:0:1") {
      is_loopback = true;
    }
  }
  if (!is_loopback && !opts_.readonly && opts_.api_key.empty()) {
    LOG(ERROR) << "JSON-RPC: refusing to listen on non-loopback address " << addr
               << " with write methods enabled and no API key. "
               << "Set --json-rpc-readonly or --json-rpc-api-key.";
    http_ = {};
    return;
  }
  if (!is_loopback && opts_.cors_origin == "*" && !opts_.readonly) {
    LOG(WARNING) << "JSON-RPC: serving non-loopback address " << addr
                 << " with CORS Access-Control-Allow-Origin=\"*\" while write "
                 << "methods are enabled. Set --json-rpc-cors-origin to a "
                 << "specific origin in production.";
  }
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
  // Codex audit (round 1, finding #2): never log the raw URL — query strings
  // can carry the API key (X-API-Key fallback) or other operator secrets and
  // this log line runs BEFORE auth. Strip the query string for logging only;
  // the live `url` value below is still used unmodified for routing.
  {
    auto qpos = url.find('?');
    auto path = qpos == std::string::npos ? url : url.substr(0, qpos);
    LOG(INFO) << "json-rpc: received " << method << " " << path
              << " payload_completed=" << payload->parse_completed()
              << " ready_bytes=" << payload->ready_bytes();
  }

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

  // GET /api-info — machine-readable API metadata (no auth required)
  if (method == "GET" && (url == "/api-info" || url == "/api-info/")) {
    std::string body =
        "{\n"
        "  \"name\": \"TOS JSON-RPC API\",\n"
        "  \"version\": \"1.0.0\",\n"
        "  \"methods_count\": 47,\n"
        "  \"endpoints\": {\n"
        "    \"jsonrpc\": \"/jsonRPC\",\n"
        "    \"health\": \"/healthcheck\",\n"
        "    \"readyz\": \"/readyz\",\n"
        "    \"api_info\": \"/api-info\",\n"
        "    \"metrics\": \"http://localhost:9100/metrics\"\n"
        "  },\n"
        "  \"openapi_spec\": \"https://github.com/tosnetwork/tos/blob/main/doc/openapi.yaml\"\n"
        "}";

    auto response = http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
    response->add_header({"Content-Type", "application/json"});
    response->add_header({"Access-Control-Allow-Origin", opts_.cors_origin});
    response->add_header({"Transfer-Encoding", "Chunked"});
    response->complete_parse_header();

    auto resp_payload = response->create_empty_payload().move_as_ok();
    resp_payload->add_chunk(td::BufferSlice(body));
    resp_payload->complete_parse();

    promise.set_value({std::move(response), std::move(resp_payload)});
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
    else if (path == "/getAccountCapability")   rest_method = "getAccountCapability";
    else if (path == "/getAccountDelegations")  rest_method = "getAccountDelegations";
    else if (path == "/getAccountSessions")     rest_method = "getAccountSessions";
    else if (path == "/getAccountAgents")       rest_method = "getAccountAgents";
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
      auto json_str = query_string_to_json(strip_api_key_param(query_string));
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

    // Match ANY known API method path for POST REST (body = params JSON, no envelope).
    // This matches HTTP API behavior where ALL methods accept POST.
    // /jsonRPC is NOT matched here — it uses the standard JSON-RPC envelope.
    static const std::set<std::string> post_rest_paths = {
        "/detectAddress", "/detectHash", "/packAddress", "/unpackAddress",
        "/getAddressInformation", "/getExtendedAddressInformation",
        "/getAccountCapability", "/getAccountDelegations", "/getAccountSessions", "/getAccountAgents",
        "/getWalletInformation", "/getAddressBalance", "/getAddressState",
        "/getTokenData",
        "/getMasterchainInfo", "/getConsensusBlock", "/lookupBlock",
        "/shards", "/getShards", "/getBlockHeader",
        "/getMasterchainBlockSignatures", "/getShardBlockProof", "/getOutMsgQueueSize",
        "/getBlockTransactions", "/getBlockTransactionsExt",
        "/getTransactions", "/getTransactionsStd",
        "/tryLocateTx", "/tryLocateResultTx", "/tryLocateSourceTx",
        "/getConfigParam", "/getConfigAll", "/getLibraries",
        "/runGetMethod", "/runGetMethodStd",
        "/sendBoc", "/sendBocReturnHash", "/sendBocReturnHashNoError",
        "/sendQuery", "/estimateFee",
        "/buildTransactionIntent", "/getSigningPayload", "/submitSignedTransaction",
        "/grantAccountDelegation", "/revokeAccountDelegation",
        "/grantAccountSession", "/revokeAccountSession",
        "/grantAccountAgent", "/revokeAccountAgent"
    };
    if (post_rest_paths.count(post_path)) {
      std::string rest_method = post_path.substr(1);  // strip leading /
      // Read body and dispatch as REST (body = params JSON object)
      // IMPORTANT: completed() must NOT call payload_->get_slice() directly,
      // because it runs inside HttpPayload::parse() which may hold mutex_.
      // Defer body read to actor scheduler via send_closure, same fix as BodyWaiter.
      class PostRestWaiter : public http::HttpPayload::Callback {
       public:
        PostRestWaiter(td::actor::ActorId<JsonRpcServer> server, PayloadPtr payload,
                       std::string method, td::Promise<HttpReturn> promise)
            : server_(server), payload_(std::move(payload)),
              method_(std::move(method)), promise_(std::move(promise)) {}
        void run(size_t) override {}
        void completed() override {
          if (fired_) return;  // one-shot guard
          fired_ = true;
          td::actor::send_closure(server_, &JsonRpcServer::on_post_rest_body_ready,
                                  std::move(payload_), std::move(method_), std::move(promise_));
        }
       private:
        td::actor::ActorId<JsonRpcServer> server_;
        PayloadPtr payload_;
        std::string method_;
        td::Promise<HttpReturn> promise_;
        bool fired_{false};
      };
      if (payload->parse_completed()) {
        auto body_r = drain_payload_body(payload);
        if (body_r.is_error()) {
          // REST POST endpoint — TVM-style error envelope (HTTP 422)
          promise.set_value(make_json_error(-32600, "Request body too large",
                                            "null", opts_.cors_origin));
          return;
        }
        process_rest_post_body(body_r.move_as_ok(), std::move(rest_method),
                               std::move(promise));
      } else {
        payload->add_callback(std::make_unique<PostRestWaiter>(
            actor_id(this), payload, std::move(rest_method), std::move(promise)));
      }
      return;
    }
  }

  // Accept POST on /jsonRPC (canonical) and any other path (backward compat)

  if (payload->parse_completed()) {
    auto body_r = drain_payload_body(payload);
    if (body_r.is_error()) {
      // JSON-RPC envelope path — emit spec-shape so generic clients decode it.
      promise.set_value(make_eth_json_error(-32600, "Request body too large",
                                            "null", opts_.cors_origin));
      return;
    }
    process_body(body_r.move_as_ok(), "", std::move(promise));
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
    promise.set_value(make_eth_json_error(-32603, "Internal error: missing request payload", "null",
                                          opts_.cors_origin));
    return;
  }
  // Safe to call get_slice() here — we are in the actor scheduler, NOT inside
  // HttpPayload::parse()'s mutex. This breaks the deadlock chain.
  auto body_r = drain_payload_body(payload);
  if (body_r.is_error()) {
    promise.set_value(make_eth_json_error(-32600, "Request body too large", "null",
                                          opts_.cors_origin));
    return;
  }
  process_body(body_r.move_as_ok(), "", std::move(promise));
}

// JSON-RPC 2.0 batch request cap.  Anything larger gets rejected with
// -32600 "Batch too large".  100 mirrors what most production indexers
// (ethers BatchProvider, web3.js BatchRequest) settle on; Blockscout's
// catchup uses ~50.
static constexpr std::size_t kJsonRpcMaxBatchSize = 100;

void JsonRpcServer::process_body(td::BufferSlice body, std::string req_id,
                                 td::Promise<HttpReturn> promise) {
  // NOTE: All JSON-RPC envelope errors below use `make_eth_json_error`
  // (spec-compliant `{jsonrpc, id, error:{code, message}}`, HTTP 200) so
  // that ethers/viem/Blockscout-style clients can decode them.  The
  // legacy `make_json_error` (`{ok:false, error:<str>, code}` + mapped
  // HTTP status) is retained for the dedicated REST endpoints under
  // `process_rest_post_body` whose Python tests still depend on it.
  if (body.empty()) {
    promise.set_value(make_eth_json_error(-32700, "Empty request body", req_id, opts_.cors_origin));
    return;
  }

  auto json_r = td::json_decode(body.as_slice());
  if (json_r.is_error()) {
    promise.set_value(make_eth_json_error(-32700, "Parse error: invalid JSON",
                                          req_id, opts_.cors_origin));
    return;
  }

  auto json = json_r.move_as_ok();

  // ── JSON-RPC 2.0 batch request ──────────────────────────────────────
  if (json.type() == td::JsonValue::Type::Array) {
    auto &arr = json.get_array();
    // Per spec: empty array → single -32600 error response (NOT an
    // empty array).
    if (arr.empty()) {
      promise.set_value(make_eth_json_error(-32600, "Invalid Request: empty batch",
                                            "null", opts_.cors_origin));
      return;
    }
    if (arr.size() > kJsonRpcMaxBatchSize) {
      promise.set_value(make_eth_json_error(
          -32600,
          PSTRING() << "Batch too large: max " << kJsonRpcMaxBatchSize
                    << " requests, got " << arr.size(),
          "null", opts_.cors_origin));
      return;
    }
    std::vector<td::JsonValue> elements;
    elements.reserve(arr.size());
    for (auto &e : arr) {
      elements.push_back(std::move(e));
    }
    process_batch(std::move(elements), std::move(promise));
    return;
  }

  if (json.type() != td::JsonValue::Type::Object) {
    promise.set_value(make_eth_json_error(-32600, "Invalid Request: expected JSON object or array",
                                          req_id, opts_.cors_origin));
    return;
  }

  process_single_object_request(std::move(json), std::move(promise));
}

// JSON-RPC 2.0 single object dispatch — extracted from process_body so the
// batch handler can re-use it.  `req` MUST be a JSON Object (caller checks).
void JsonRpcServer::process_single_object_request(td::JsonValue req,
                                                   td::Promise<HttpReturn> promise) {
  auto &obj = req.get_object();

  // Extract request ID — store as JSON literal to preserve type in response
  // (JSON-RPC 2.0 requires echoing the id type exactly).
  std::string req_id;
  {
    auto id_val = obj.extract_field("id");
    if (id_val.type() == td::JsonValue::Type::String) {
      req_id = PSTRING() << td::JsonString(td::Slice(id_val.get_string()));
    } else if (id_val.type() == td::JsonValue::Type::Number) {
      req_id = id_val.get_number().str();  // numeric literal, no quotes
    } else {
      // Null id, missing id, or non-stringy/numeric id → echo as JSON
      // null per spec.  Note: in single-request mode this still emits
      // a response.  In batch mode the batch driver detects "no id"
      // (notification) by re-checking the original element.
      req_id = "null";
    }
  }

  // Extract method
  auto method_r = obj.get_required_string_field("method");
  if (method_r.is_error()) {
    promise.set_value(make_eth_json_error(-32600, "Missing or invalid 'method' field", req_id));
    return;
  }
  std::string method = method_r.move_as_ok();

  // Extract params (optional)
  auto params_val = obj.extract_field("params");
  if (params_val.type() == td::JsonValue::Type::Null) {
    params_val = td::JsonValue::make_object(td::JsonObject());
  }

  // Readonly gate (centralized — see is_write_method). Must run BEFORE the
  // per-method fast paths below or `eth_sendRawTransaction` / `uno_send*`
  // would bypass `--json-rpc-readonly`.
  if (opts_.readonly && is_write_method(method)) {
    promise.set_value(make_eth_json_error(
        -32601, "Write methods are disabled (server is in readonly mode)",
        req_id, opts_.cors_origin));
    return;
  }

  // eth_sendRawTransaction: route to async handler (submits to ExtMessagePool)
  if (method == "eth_sendRawTransaction") {
    handle_eth_sendRawTransaction(params_val, std::move(req_id), std::move(promise));
    return;
  }

  // uno_sendMineUno: route to async handler (submits a wc=2 ext_in_msg
  // through the same liteServer_sendMessage pipe as eth_sendRawTransaction).
  // Intercepted BEFORE the `is_uno_rpc_method` registry below — that
  // registry covers read-only uno_* methods that don't need access to
  // `send_liteserver_query`.
  if (method == "uno_sendMineUno") {
    handle_uno_sendMineUno(params_val, std::move(req_id), std::move(promise));
    return;
  }

  // uno_getMineState: synchronous read of the live MineUno consensus
  // state. Lives in json-rpc-server-uno.cpp because the response shape
  // and rate-limit policy are validator-engine concerns; the underlying
  // accessor is bound by `init_uno_workchain` in uno/core/init.cpp.
  if (method == "uno_getMineState") {
    promise.set_value(
        handle_uno_get_mine_state(std::move(req_id), opts_.cors_origin));
    return;
  }

  // Ethereum JSON-RPC sends params as arrays.  Handle eth_* methods with
  // array params directly, before the object-params check.
  if (params_val.type() == td::JsonValue::Type::Array &&
      evm_workchain::is_eth_rpc_method(method)) {
    td::JsonBuilder jb;
    jb.enter_value() << params_val;
    std::string params_str = jb.string_builder().as_cslice().str();

    auto result = evm_workchain::handle_eth_rpc(method, params_str, req_id);
    if (result) {
      // The EVM RPC handler returns a complete JSON-RPC response string.
      // Wrap it in a raw HTTP response.
      promise.set_value(make_raw_json_response(result->json, opts_.cors_origin));
    } else {
      promise.set_value(make_eth_json_error(-32601, PSTRING() << "Method not found: " << method, req_id));
    }
    return;
  }

  // Uno workchain (wc=2) JSON-RPC: same array-params convention as eth_*.
  if (params_val.type() == td::JsonValue::Type::Array &&
      uno_workchain::is_uno_rpc_method(method)) {
    td::JsonBuilder jb;
    jb.enter_value() << params_val;
    std::string params_str = jb.string_builder().as_cslice().str();

    auto result = uno_workchain::handle_uno_rpc(method, params_str, req_id);
    if (result) {
      promise.set_value(make_raw_json_response(result->json, opts_.cors_origin));
    } else {
      promise.set_value(make_eth_json_error(-32601, PSTRING() << "Method not found: " << method, req_id));
    }
    return;
  }

  if (params_val.type() != td::JsonValue::Type::Object) {
    // Method is unknown to the eth_* registry AND params is not an object.
    // Don't bail with "'params' must be an object" — that would mask a
    // real "Method not found" for callers who probe with array params
    // (Blockscout's `txpool_content` polling, geth-style probes, etc.).
    // Substitute an empty params object and let dispatch_method emit
    // either the method-not-found error or a per-handler missing-field
    // error.  Both are spec-shape via make_eth_json_error.
    td::JsonObject empty_params;
    cached_dispatch_method(std::move(method), empty_params,
                           std::move(req_id), std::move(promise));
    return;
  }

  cached_dispatch_method(std::move(method), params_val.get_object(),
                         std::move(req_id), std::move(promise));
}

// ── JSON-RPC 2.0 batch dispatch ────────────────────────────────────────
//
// The batch is processed sequentially: dispatch element N, on completion
// dispatch element N+1, and on completion of the last element emit the
// JSON array of responses.  Sequential dispatch keeps memory bounded
// (one in-flight liteserver query per batch instead of N) and avoids
// racing the cache_misses_/active_requests_ counters.  The 100-element
// cap (kJsonRpcMaxBatchSize) means worst-case latency is ~100×
// per-method service time, well under the 30 s request_timeout.
//
// Notifications (request elements with no `id` field) are dispatched
// like any other request, but their response is dropped from the output
// array per spec.  If every element is a notification the response is
// HTTP 204 No Content.

struct JsonRpcServer::BatchState {
  std::vector<td::JsonValue> elements;
  std::vector<bool> is_notification;
  std::vector<std::string> responses;  // empty = notification, dropped
  std::size_t cursor{0};
  td::Promise<HttpReturn> final_promise;
  std::string cors;
};

void JsonRpcServer::process_batch(std::vector<td::JsonValue> elements,
                                  td::Promise<HttpReturn> promise) {
  // Per-element notification flag.  A request is a notification iff its
  // `id` field is absent (NOT iff it's null — null is a valid id).  We
  // detect this BEFORE process_single_object_request consumes the field.
  std::vector<bool> is_notification;
  is_notification.reserve(elements.size());
  for (auto &el : elements) {
    if (el.type() != td::JsonValue::Type::Object) {
      // Spec: per-element invalid request → an error response with id null
      // in the output array.  We synthesize one below in the loop.
      is_notification.push_back(false);
      continue;
    }
    auto &obj = el.get_object();
    bool has_id = false;
    for (auto &fv : obj.field_values_) {
      if (fv.first == "id") { has_id = true; break; }
    }
    is_notification.push_back(!has_id);
  }

  auto state = std::make_shared<BatchState>();
  state->elements = std::move(elements);
  state->is_notification = std::move(is_notification);
  state->responses.resize(state->elements.size());
  state->final_promise = std::move(promise);
  state->cors = opts_.cors_origin;

  process_batch_step(state);
}

void JsonRpcServer::process_batch_step(std::shared_ptr<BatchState> state) {
  // Drain synchronous (non-Object) elements.
  while (state->cursor < state->elements.size()) {
    std::size_t i = state->cursor;
    auto &el = state->elements[i];
    if (el.type() != td::JsonValue::Type::Object) {
      auto err = make_eth_json_error(
          -32600, "Invalid Request: batch element is not a JSON object",
          "null", state->cors);
      state->responses[i] = extract_response_body(err);
      state->cursor++;
      continue;
    }

    bool is_notif = state->is_notification[i];
    auto self = actor_id(this);
    auto sub_promise = td::PromiseCreator::lambda(
        [self, state, i, is_notif](td::Result<HttpReturn> R) mutable {
          if (R.is_error()) {
            // Internal error becomes an element-level error with null id.
            auto err = JsonRpcServer::make_eth_json_error(
                -32603, R.error().message().str(), "null", state->cors);
            state->responses[i] = JsonRpcServer::extract_response_body(err);
          } else {
            auto ret = R.move_as_ok();
            std::string body = JsonRpcServer::extract_response_body(ret);
            if (is_notif) {
              state->responses[i] = "";  // dropped from output array
            } else {
              state->responses[i] = std::move(body);
            }
          }
          state->cursor++;
          // Re-enter on the actor scheduler — keeps the stack flat and
          // ordering deterministic.
          td::actor::send_closure(self, &JsonRpcServer::process_batch_step, state);
        });

    auto el_moved = std::move(el);
    process_single_object_request(std::move(el_moved), std::move(sub_promise));
    return;  // wait for sub_promise to fire
  }
  // All elements done — emit the result array (or 204 if all-notifications).
  finalize_batch(std::move(state));
}

void JsonRpcServer::finalize_batch(std::shared_ptr<BatchState> state) {
  // Filter notifications out of the output.
  std::string body = "[";
  bool first = true;
  for (std::size_t i = 0; i < state->responses.size(); i++) {
    if (state->responses[i].empty()) continue;  // dropped notification
    if (!first) body += ",";
    first = false;
    body += state->responses[i];
  }
  body += "]";

  if (first) {
    // All elements were notifications — spec says return nothing.  HTTP
    // 204 No Content with an empty body is the canonical interpretation.
    state->final_promise.set_value(make_no_content(state->cors));
    return;
  }
  state->final_promise.set_value(make_json_array_response(std::move(body), state->cors));
}

// ─── POST REST body processing (body = params JSON, no jsonrpc envelope) ──

void JsonRpcServer::on_post_rest_body_ready(PayloadPtr payload, std::string method,
                                            td::Promise<HttpReturn> promise) {
  // Safe to call get_slice() here — we are in the actor scheduler, NOT inside
  // HttpPayload::parse()'s callback chain. Breaks the deadlock.
  auto body_r = drain_payload_body(payload);
  if (body_r.is_error()) {
    promise.set_value(make_json_error(-32600, "Request body too large", "null",
                                      opts_.cors_origin));
    return;
  }
  process_rest_post_body(body_r.move_as_ok(), std::move(method), std::move(promise));
}

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
  // Track per-method request count
  requests_total_.fetch_add(1);
  active_requests_.fetch_add(1);
  method_requests_->label(method)->add(1);

  // Wrap the promise to track completion and errors
  auto method_copy = method;
  promise = td::PromiseCreator::lambda(
      [this, method_copy, inner = std::move(promise)](td::Result<HttpReturn> R) mutable {
        active_requests_.fetch_sub(1);
        if (R.is_error()) {
          requests_errors_.fetch_add(1);
          method_errors_->label(method_copy)->add(1);
          inner.set_error(R.move_as_error());
        } else {
          auto ret = R.move_as_ok();
          // Check if the response is an error (ok=false in the JSON body)
          // by inspecting the HTTP status code (non-200 = error)
          auto &resp = ret.first;
          if (resp) {
            // HTTP status is encoded in the status line; for simplicity,
            // count any response as success at the dispatch level.
            // Method-level errors are tracked separately.
          }
          inner.set_value(std::move(ret));
        }
      });

  // Defense-in-depth: a request that reaches dispatch_method has already been
  // gated centrally in process_single_object_request (and the REST adapters).
  // Re-check anyway so a future caller that bypasses the upper layer cannot
  // sneak through.
  if (opts_.readonly && is_write_method(method)) {
    promise.set_value(make_eth_json_error(-32601,
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
  } else if (method == "getAccountCapability") {
    handle_getAccountCapability(params, std::move(req_id), std::move(promise));
  } else if (method == "getAccountDelegations") {
    handle_getAccountDelegations(params, std::move(req_id), std::move(promise));
  } else if (method == "getAccountSessions") {
    handle_getAccountSessions(params, std::move(req_id), std::move(promise));
  } else if (method == "getAccountAgents") {
    handle_getAccountAgents(params, std::move(req_id), std::move(promise));
  } else if (method == "grantAccountDelegation") {
    handle_grantAccountDelegation(params, std::move(req_id), std::move(promise));
  } else if (method == "revokeAccountDelegation") {
    handle_revokeAccountDelegation(params, std::move(req_id), std::move(promise));
  } else if (method == "grantAccountSession") {
    handle_grantAccountSession(params, std::move(req_id), std::move(promise));
  } else if (method == "revokeAccountSession") {
    handle_revokeAccountSession(params, std::move(req_id), std::move(promise));
  } else if (method == "grantAccountAgent") {
    handle_grantAccountAgent(params, std::move(req_id), std::move(promise));
  } else if (method == "revokeAccountAgent") {
    handle_revokeAccountAgent(params, std::move(req_id), std::move(promise));
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
  } else if (method == "buildTransactionIntent") {
    handle_buildTransactionIntent(params, std::move(req_id), std::move(promise));
  } else if (method == "getSigningPayload") {
    handle_getSigningPayload(params, std::move(req_id), std::move(promise));
  } else if (method == "submitSignedTransaction") {
    handle_submitSignedTransaction(params, std::move(req_id), std::move(promise));
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
  // New APIs (HTTP API parity)
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
  }
  // --- EVM Workchain: Ethereum JSON-RPC methods ---
  else if (evm_workchain::is_eth_rpc_method(method)) {
    std::string params_str = "[]";
    if (params.field_count() > 0) {
      td::JsonBuilder jb;
      auto arr = jb.enter_array();
      for (auto& kv : params.field_values_) {
        arr.enter_value() << kv.second;
      }
      arr.leave();
      params_str = jb.string_builder().as_cslice().str();
    }
    auto result = evm_workchain::handle_eth_rpc(method, params_str, req_id);
    if (result) {
      promise.set_value(make_raw_json_response(result->json, opts_.cors_origin));
    } else {
      promise.set_value(make_eth_json_error(-32601, PSTRING() << "Method not found: " << method, req_id));
    }
  }
  // --- Uno Workchain (wc=2): validator-engine-side uno_* methods ---
  // These two methods need access to JsonRpcServer-private state
  // (`send_liteserver_query` / mine-state accessor) so they can't live
  // in the generic uno_workchain::handle_uno_rpc registry below.
  else if (method == "uno_getMineState") {
    promise.set_value(
        handle_uno_get_mine_state(std::move(req_id), opts_.cors_origin));
  }
  else if (method == "uno_sendMineUno") {
    // Object-params path: re-pack the field values into a JSON array
    // and hand off to the same async handler used by the array-params
    // fast-path in process_single_object_request.
    td::JsonBuilder jb;
    {
      auto arr = jb.enter_array();
      for (auto& kv : params.field_values_) {
        arr.enter_value() << kv.second;
      }
      arr.leave();
    }
    auto params_str = jb.string_builder().as_cslice().str();
    auto parsed = td::json_decode(td::MutableSlice(params_str));
    if (parsed.is_error()) {
      promise.set_value(make_eth_json_error(-32602,
          PSTRING() << "uno_sendMineUno: malformed params: " << parsed.error(),
          req_id));
      return;
    }
    auto val = parsed.move_as_ok();
    handle_uno_sendMineUno(val, std::move(req_id), std::move(promise));
  }
  // --- Uno Workchain (wc=2): uno_* JSON-RPC methods ---
  else if (uno_workchain::is_uno_rpc_method(method)) {
    std::string params_str = "[]";
    if (params.field_count() > 0) {
      td::JsonBuilder jb;
      auto arr = jb.enter_array();
      for (auto& kv : params.field_values_) {
        arr.enter_value() << kv.second;
      }
      arr.leave();
      params_str = jb.string_builder().as_cslice().str();
    }
    auto result = uno_workchain::handle_uno_rpc(method, params_str, req_id);
    if (result) {
      promise.set_value(make_raw_json_response(result->json, opts_.cors_origin));
    } else {
      promise.set_value(make_eth_json_error(-32601, PSTRING() << "Method not found: " << method, req_id));
    }
  }
  else {
    // Unknown method via JSON-RPC envelope dispatch — emit spec-compliant
    // error so generic ethereum tooling (Blockscout, ethers, viem, web3.py)
    // can decode it.  See process_body for the rationale.
    promise.set_value(make_eth_json_error(-32601, PSTRING() << "Method not found: " << method, req_id));
  }
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

JsonRpcServer::HttpReturn JsonRpcServer::make_raw_json_response(const std::string& json_body,
                                                                const std::string& cors_origin) {
  auto response = http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
  response->add_header({"Content-Type", "application/json"});
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();
  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice(json_body));
  payload->complete_parse();
  return {std::move(response), std::move(payload)};
}

JsonRpcServer::HttpReturn JsonRpcServer::make_json_ok(std::string result_json, std::string id,
                                                      const std::string& cors_origin) {
  if (id.empty()) id = "null";
  // TVM convention: `{ok, jsonrpc, id, result}` — the `ok` field is a
  // convenience wrapper the Python/JS test suite depends on. Ethereum
  // JSON-RPC callers (ethers/viem/web3.py) ignore it.
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
  // TVM convention: `{ok: false, jsonrpc, id, error:<string>, code}` +
  // a mapped HTTP status code. The Python test suite
  // (test/json-rpc/*.py) asserts on both `ok` and the HTTP status.
  // For Ethereum RPC use `make_eth_json_error` instead — it emits
  // the JSON-RPC 2.0 nested error shape with HTTP 200.
  std::string body = PSTRING()
      << "{\"ok\":false,\"jsonrpc\":\"2.0\",\"id\":" << id
      << ",\"error\":" << td::JsonString(td::Slice(message))
      << ",\"code\":" << code << "}";

  int http_status = 200;
  std::string http_status_text = "OK";
  if (code == -32602 || code == -32600) {
    http_status = 422; http_status_text = "Unprocessable Entity";
  } else if (code == -32603) {
    http_status = 500; http_status_text = "Internal Server Error";
  } else if (code == -32601) {
    http_status = 404; http_status_text = "Not Found";
  } else if (code == -32700) {
    http_status = 400; http_status_text = "Bad Request";
  } else if (code == -32000) {
    http_status = 401; http_status_text = "Unauthorized";
  } else if (code == 409) {
    http_status = 409; http_status_text = "Conflict";
  } else if (code < 0) {
    http_status = 500; http_status_text = "Internal Server Error";
  }

  auto response = http::HttpResponse::create("HTTP/1.1", http_status, std::move(http_status_text), false, false).move_as_ok();
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

JsonRpcServer::HttpReturn JsonRpcServer::make_eth_json_error(int code, std::string message, std::string id,
                                                              const std::string& cors_origin) {
  if (id.empty()) id = "null";
  // JSON-RPC 2.0 error: `{jsonrpc, id, error:{code, message}}`, HTTP
  // 200 always. Matches the Ethereum execution-apis contract that
  // ethers / viem / web3.py all assume.
  std::string body = PSTRING()
      << "{\"jsonrpc\":\"2.0\",\"id\":" << id
      << ",\"error\":{\"code\":" << code
      << ",\"message\":" << td::JsonString(td::Slice(message)) << "}}";

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

JsonRpcServer::HttpReturn JsonRpcServer::make_no_content(const std::string& cors_origin) {
  auto response = http::HttpResponse::create("HTTP/1.1", 204, "No Content", false, false).move_as_ok();
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Content-Length", "0"});
  response->complete_parse_header();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->complete_parse();

  return {std::move(response), std::move(payload)};
}

JsonRpcServer::HttpReturn JsonRpcServer::make_json_array_response(std::string body,
                                                                   const std::string& cors_origin) {
  auto response = http::HttpResponse::create("HTTP/1.1", 200, "OK", false, false).move_as_ok();
  response->add_header({"Content-Type", "application/json"});
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice(std::move(body)));
  payload->complete_parse();

  return {std::move(response), std::move(payload)};
}

std::string JsonRpcServer::extract_response_body(HttpReturn& ret) {
  std::string out;
  if (!ret.second) return out;
  // HttpPayload returns ONE chunk per get_slice() call — loop until drained.
  while (true) {
    auto chunk = ret.second->get_slice(1u << 20);
    if (chunk.empty()) break;
    out.append(chunk.as_slice().begin(), chunk.size());
  }
  return out;
}

JsonRpcServer::HttpReturn JsonRpcServer::make_cors_preflight(const std::string& cors_origin) {
  auto response = http::HttpResponse::create("HTTP/1.1", 204, "No Content", false, false).move_as_ok();
  response->add_header({"Access-Control-Allow-Origin", cors_origin});
  response->add_header({"Access-Control-Allow-Methods", "POST, GET, OPTIONS"});
  response->add_header({"Access-Control-Allow-Headers", "Content-Type, X-API-Key"});
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

static bool constant_time_compare(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) return false;
  volatile unsigned char result = 0;
  for (size_t i = 0; i < a.size(); i++) {
    result |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
  }
  return result == 0;
}

// Centralized write-method registry.
// Codex audit (round 1, finding #1): the per-method fast path for
// `eth_sendRawTransaction`, `uno_sendMineUno`, and the `uno_*` write methods
// (e.g. `uno_sendTransfer`) used to short-circuit `process_single_object_request`
// BEFORE the readonly gate at `dispatch_method`. Readonly mode therefore only
// blocked legacy `sendBoc`/`sendQuery`/account-write methods, not EVM/UNO
// submissions. Centralize here so any caller (single-object dispatch, batch,
// REST POST, GET adapter) checks once.
bool JsonRpcServer::is_write_method(const std::string &method) {
  static const std::set<std::string> writes = {
      // Legacy TOS write methods (also gated in dispatch_method, kept for parity).
      "sendBoc", "sendBocReturnHash", "sendBocReturnHashNoError", "sendQuery",
      "submitSignedTransaction",
      "grantAccountDelegation", "revokeAccountDelegation",
      "grantAccountSession", "revokeAccountSession",
      "grantAccountAgent", "revokeAccountAgent",
      // EVM workchain (wc=1).
      "eth_sendRawTransaction",
      // Uno workchain (wc=2): both the synchronous Transfer admission path
      // and the asynchronous MineUno submission path emit external messages.
      "uno_sendTransfer",
      "uno_sendMineUno",
  };
  return writes.count(method) > 0;
}

bool JsonRpcServer::check_api_key(const RequestPtr &request,
                                  td::Promise<HttpReturn> &promise) {
  if (opts_.api_key.empty()) {
    return true;  // no auth configured
  }

  // Codex audit (round 1, finding #2): only the X-API-Key header is accepted.
  // The previous `?api_key=...` query-string fallback leaked the key into
  // access logs, browser history, intermediary proxies, and our own
  // `LOG(INFO) << "json-rpc: received ..."` (which ran before auth). Header-
  // only is the standard practice and keeps the secret out of URLs.
  auto key_header = request->get_header("X-API-Key");
  if (!key_header.empty() && constant_time_compare(key_header, opts_.api_key)) {
    return true;
  }

  // Auth failed
  promise.set_value(make_json_unauthorized(opts_.cors_origin));
  return false;
}

// ─── Response cache ─────────────────────────────────────────────────────

const std::set<std::string> &JsonRpcServer::cacheable_methods() {
  static const std::set<std::string> methods = {
      "getMasterchainInfo", "getConfigParam", "getConfigAll",
      "getAddressInformation", "getAccountCapability",
      "getAccountDelegations", "getAccountSessions", "getAccountAgents",
      "getWalletInformation", "getAddressBalance",
      "getAddressState", "getBlockHeader", "lookupBlock", "shards",
      "getConsensusBlock", "getOutMsgQueueSize"
  };
  return methods;
}

void JsonRpcServer::alarm() {
  if (opts_.cache_ttl > 0 && !cache_.empty()) {
    cache_.evict_expired();
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
  auto cached = cache_.lookup(cache_key);
  if (cached.has_value()) {
    // Cache hit — rebuild HTTP response from the cached body string, substituting
    // the current request's id so that each caller gets the correct "id" field.
    cache_hits_.fetch_add(1);
    promise.set_value(make_json_ok(*cached, req_id));
    return;
  }

  // Cache miss — dispatch normally but wrap the promise to capture the result
  cache_misses_.fetch_add(1);
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
          //
          // HttpPayload stores the body in 16 KiB chunks and `get_slice()`
          // returns ONE chunk per call.  Loop until exhausted so responses
          // larger than 16 KiB (e.g. blocks with many transactions) are
          // captured correctly for caching.  No upper cap here — the cache
          // layer enforces its own `cache_max_body_bytes` budget.
          std::string body_str;
          while (true) {
            auto chunk = result.second->get_slice(1u << 20);
            if (chunk.empty()) break;
            body_str.append(chunk.as_slice().begin(), chunk.size());
          }

          if (body_str.find("\"ok\":true") != std::string::npos) {
            // Extract the "result" JSON value using the td::JsonValue parser
            // instead of fragile string searching.  This is safe even when
            // the result payload itself contains a literal "result": string.
            auto json_r = td::json_decode(td::MutableSlice(body_str));
            if (json_r.is_ok() && json_r.ok().type() == td::JsonValue::Type::Object) {
              auto &obj = json_r.ok_ref().get_object();
              for (auto &fv : obj.field_values_) {
                if (fv.first == "result") {
                  auto encoded = td::json_encode<std::string>(fv.second);
                  if (cache_.store(cache_key, encoded,
                                   td::Timestamp::in(static_cast<double>(ttl)))) {
                    auto cached_value = cache_.lookup(cache_key);
                    if (cached_value.has_value()) {
                      orig_promise.set_value(make_json_ok(*cached_value, req_id, cors));
                      return;
                    }
                  }
                  orig_promise.set_value(make_json_ok(std::move(encoded), req_id, cors));
                  return;
                }
              }
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

// ─── Prometheus metrics collection ──────────────────────────────────────

void JsonRpcServer::collect(metrics::MetricsPromise P) {
  metrics::MetricSet set{{}};

  // Scalar counters
  set.families.push_back(
      metrics::MetricFamily::make_scalar("jsonrpc_requests_total", "counter",
          static_cast<double>(requests_total_.load()),
          "Total JSON-RPC requests received"));
  set.families.push_back(
      metrics::MetricFamily::make_scalar("jsonrpc_errors_total", "counter",
          static_cast<double>(requests_errors_.load()),
          "Total JSON-RPC requests that resulted in errors"));
  set.families.push_back(
      metrics::MetricFamily::make_scalar("jsonrpc_active_requests", "gauge",
          static_cast<double>(active_requests_.load()),
          "Currently in-flight JSON-RPC requests"));
  set.families.push_back(
      metrics::MetricFamily::make_scalar("jsonrpc_cache_hits_total", "counter",
          static_cast<double>(cache_hits_.load()),
          "JSON-RPC response cache hits"));
  set.families.push_back(
      metrics::MetricFamily::make_scalar("jsonrpc_cache_misses_total", "counter",
          static_cast<double>(cache_misses_.load()),
          "JSON-RPC response cache misses"));
  set.families.push_back(
      metrics::MetricFamily::make_scalar("jsonrpc_cache_entries", "gauge",
          static_cast<double>(cache_.size()),
          "Current number of entries in the response cache"));

  // Per-method request and error counters
  set = std::move(set).join(method_requests_->collect());
  set = std::move(set).join(method_errors_->collect());

  // Uptime
  if (start_time_) {
    double uptime = td::Time::now() - start_time_.at();
    set.families.push_back(
        metrics::MetricFamily::make_scalar("jsonrpc_uptime_seconds", "gauge",
            uptime, "JSON-RPC server uptime in seconds"));
  }

  P.set_value(std::move(set));
}

}  // namespace tos
