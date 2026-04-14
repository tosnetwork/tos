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

#include "http/http-server.h"
#include "metrics/metrics-collectors.h"
#include "td/actor/actor.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Time.h"
#include "validator/validator.h"

#include <set>
#include <unordered_map>

namespace tos {

class JsonRpcServer final : public td::actor::Actor, public virtual metrics::AsyncCollector {
 public:
  struct Options {
    bool readonly = false;           // disable sendBoc/sendBocReturnHash/sendQuery
    std::string cors_origin = "*";   // Access-Control-Allow-Origin value
    td::int32 readyz_threshold = 60; // sync lag threshold in seconds for /readyz
    double request_timeout = 30.0;   // per-request timeout in seconds (0 = no timeout)
    std::string api_key;             // empty = no auth required
    td::int32 cache_ttl = 0;        // seconds, 0 = disabled
  };

  static td::actor::ActorOwn<JsonRpcServer> create(
      td::actor::ActorId<validator::ValidatorManagerInterface> validator_manager,
      Options options);

  void listen(td::IPAddress addr);
  void collect(metrics::MetricsPromise P) override;

  JsonRpcServer(
      td::actor::ActorId<validator::ValidatorManagerInterface> validator_manager,
      Options options);

 private:
  using RequestPtr = std::unique_ptr<http::HttpRequest>;
  using ResponsePtr = std::unique_ptr<http::HttpResponse>;
  using PayloadPtr = std::shared_ptr<http::HttpPayload>;
  using HttpReturn = std::pair<ResponsePtr, PayloadPtr>;

  class HttpCallback : public http::HttpServer::Callback {
   public:
    explicit HttpCallback(td::actor::ActorId<JsonRpcServer> server);
    void receive_request(RequestPtr request, PayloadPtr payload,
                         td::Promise<HttpReturn> promise) override;
   private:
    td::actor::ActorId<JsonRpcServer> server_;
  };
  friend HttpCallback;

  void on_request(RequestPtr request, PayloadPtr payload,
                  td::Promise<HttpReturn> promise);
  // Called by BodyWaiter via actor message — reads payload OUTSIDE HttpPayload mutex.
  void on_body_ready(PayloadPtr payload, td::Promise<HttpReturn> promise);
  void process_body(td::BufferSlice body, std::string req_id,
                    td::Promise<HttpReturn> promise);
  void process_rest_post_body(td::BufferSlice body, std::string method,
                              td::Promise<HttpReturn> promise);
  // Called by PostRestWaiter via actor message — reads payload OUTSIDE mutex.
  void on_post_rest_body_ready(PayloadPtr payload, std::string method,
                               td::Promise<HttpReturn> promise);
  void dispatch_method(std::string method, td::JsonObject &params,
                       std::string req_id, td::Promise<HttpReturn> promise);

  // Method handlers — existing
  void handle_sendBoc(td::JsonObject &params, std::string req_id,
                      td::Promise<HttpReturn> promise);
  void handle_getConfigParam(td::JsonObject &params, std::string req_id,
                             td::Promise<HttpReturn> promise);
  void handle_getAddressInformation(td::JsonObject &params, std::string req_id,
                                    td::Promise<HttpReturn> promise);
  void handle_getExtendedAddressInformation(td::JsonObject &params,
                                            std::string req_id,
                                            td::Promise<HttpReturn> promise);
  void handle_runGetMethod(td::JsonObject &params, std::string req_id,
                           td::Promise<HttpReturn> promise);
  void handle_getWalletInformation(td::JsonObject &params, std::string req_id,
                                   td::Promise<HttpReturn> promise);

  // Method handlers — block/chain read APIs
  void handle_getMasterchainInfo(td::JsonObject &params, std::string req_id,
                                 td::Promise<HttpReturn> promise);
  void handle_getConsensusBlock(td::JsonObject &params, std::string req_id,
                                td::Promise<HttpReturn> promise);
  void handle_lookupBlock(td::JsonObject &params, std::string req_id,
                          td::Promise<HttpReturn> promise);
  void handle_shards(td::JsonObject &params, std::string req_id,
                     td::Promise<HttpReturn> promise);
  void handle_getBlockHeader(td::JsonObject &params, std::string req_id,
                             td::Promise<HttpReturn> promise);
  void handle_getBlockTransactions(td::JsonObject &params, std::string req_id,
                                   td::Promise<HttpReturn> promise);
  void handle_getTransactions(td::JsonObject &params, std::string req_id,
                              td::Promise<HttpReturn> promise);
  void handle_getBlockTransactionsExt(td::JsonObject &params, std::string req_id,
                                      td::Promise<HttpReturn> promise);

  // Method handlers — transaction lookup APIs
  void handle_tryLocateTx(td::JsonObject &params, std::string req_id,
                          td::Promise<HttpReturn> promise);
  void handle_tryLocateResultTx(td::JsonObject &params, std::string req_id,
                                td::Promise<HttpReturn> promise);
  void handle_tryLocateSourceTx(td::JsonObject &params, std::string req_id,
                                td::Promise<HttpReturn> promise);

  // Method handlers — block proof / signature APIs
  void handle_getMasterchainBlockSignatures(td::JsonObject &params, std::string req_id,
                                            td::Promise<HttpReturn> promise);
  void handle_getShardBlockProof(td::JsonObject &params, std::string req_id,
                                 td::Promise<HttpReturn> promise);

  // Method handlers — send family
  void handle_sendBocReturnHash(td::JsonObject &params, std::string req_id,
                                td::Promise<HttpReturn> promise);
  void handle_sendQuery(td::JsonObject &params, std::string req_id,
                        td::Promise<HttpReturn> promise);
  void handle_estimateFee(td::JsonObject &params, std::string req_id,
                          td::Promise<HttpReturn> promise);

  // Method handlers — convenience / address APIs
  void handle_getAddressBalance(td::JsonObject &params, std::string req_id,
                                td::Promise<HttpReturn> promise);
  void handle_getAddressState(td::JsonObject &params, std::string req_id,
                              td::Promise<HttpReturn> promise);
  void handle_packAddress(td::JsonObject &params, std::string req_id,
                          td::Promise<HttpReturn> promise);
  void handle_unpackAddress(td::JsonObject &params, std::string req_id,
                            td::Promise<HttpReturn> promise);
  void handle_detectAddress(td::JsonObject &params, std::string req_id,
                            td::Promise<HttpReturn> promise);

  // Method handlers — library & token data APIs
  void handle_getLibraries(td::JsonObject &params, std::string req_id,
                           td::Promise<HttpReturn> promise);
  void handle_getTokenData(td::JsonObject &params, std::string req_id,
                           td::Promise<HttpReturn> promise);

  // Method handlers — new APIs (parity with ton-http-api-cpp)
  void handle_detectHash(td::JsonObject &params, std::string req_id,
                         td::Promise<HttpReturn> promise);
  void handle_getOutMsgQueueSize(td::JsonObject &params, std::string req_id,
                                 td::Promise<HttpReturn> promise);
  void handle_getConfigAll(td::JsonObject &params, std::string req_id,
                           td::Promise<HttpReturn> promise);
  void handle_getTransactionsStd(td::JsonObject &params, std::string req_id,
                                 td::Promise<HttpReturn> promise);
  void handle_runGetMethodStd(td::JsonObject &params, std::string req_id,
                              td::Promise<HttpReturn> promise);
  void handle_sendBocReturnHashNoError(td::JsonObject &params, std::string req_id,
                                       td::Promise<HttpReturn> promise);

  // Readiness probe (async — queries liteserver for sync state)
  void handle_readyz(td::Promise<HttpReturn> promise);

  // Send a TL-serialized liteserver query to the validator manager
  void send_liteserver_query(td::BufferSlice query,
                             td::Promise<td::BufferSlice> promise);

  // Utility: build JSON-RPC response
  static HttpReturn make_json_ok(std::string result_json, std::string id,
                                 const std::string& cors_origin = "*");
  static HttpReturn make_json_error(int code, std::string message, std::string id,
                                    const std::string& cors_origin = "*");
  static HttpReturn make_health_ok(const std::string& cors_origin = "*");
  static HttpReturn make_cors_preflight(const std::string& cors_origin = "*");
  static HttpReturn make_text_response(int status_code, std::string status_text,
                                       std::string body,
                                       const std::string& cors_origin = "*");
  // Return HTTP 401 with JSON-RPC error body
  static HttpReturn make_json_unauthorized(const std::string& cors_origin = "*");

  // API key authentication helper — returns true if request is authorized.
  // When false is returned, a 401 response has already been sent via promise.
  bool check_api_key(const RequestPtr &request,
                     td::Promise<HttpReturn> &promise);

  // Cache-aware dispatch: checks cache for read-only methods, delegates to
  // dispatch_method() on miss, and stores successful results.
  void cached_dispatch_method(std::string method, td::JsonObject &params,
                              std::string req_id, td::Promise<HttpReturn> promise);

  void alarm() override;

  // ── Response cache ───────────────────────────────────────────────────
  struct CacheEntry {
    std::string response_json;
    td::Timestamp expires_at;
  };
  std::unordered_map<std::string, CacheEntry> cache_;

  static const std::set<std::string> &cacheable_methods();
  td::int32 cache_ttl_for_method(const std::string &method) const;

  td::actor::ActorId<validator::ValidatorManagerInterface> validator_manager_;
  td::actor::ActorOwn<http::HttpServer> http_;
  Options opts_;
  td::uint32 consensus_block_seqno_{0};
  td::int64 consensus_block_timestamp_{0};

  // ── Statistics ───────────────────────────────────────────────────────
  td::Timestamp start_time_;
  std::atomic<td::uint64> requests_total_{0};
  std::atomic<td::uint64> requests_errors_{0};
  std::atomic<td::uint64> cache_hits_{0};
  std::atomic<td::uint64> cache_misses_{0};
  std::atomic<td::uint64> active_requests_{0};

  // Per-method request count (method name → count)
  metrics::Labeled<std::string, metrics::AtomicCounter<td::uint64>>::Ptr
      method_requests_ = metrics::Labeled<std::string, metrics::AtomicCounter<td::uint64>>::make(
          "method", "jsonrpc_method_requests_total", std::optional<std::string>("JSON-RPC requests by method"));
  metrics::Labeled<std::string, metrics::AtomicCounter<td::uint64>>::Ptr
      method_errors_ = metrics::Labeled<std::string, metrics::AtomicCounter<td::uint64>>::make(
          "method", "jsonrpc_method_errors_total", std::optional<std::string>("JSON-RPC errors by method"));
};

}  // namespace tos
