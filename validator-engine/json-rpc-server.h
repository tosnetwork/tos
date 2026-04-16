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

#include <cstddef>

#include "http/http-server.h"
#include "metrics/metrics-collectors.h"
#include "td/actor/actor.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Time.h"
#include "validator/validator.h"
#include "block/block.h"

#include <list>
#include <set>
#include <unordered_map>

namespace tos {

class JsonRpcResponseCache {
 public:
  JsonRpcResponseCache(std::size_t max_entries, std::size_t max_body_bytes)
      : max_entries_(max_entries), max_body_bytes_(max_body_bytes) {
  }

  bool empty() const noexcept {
    return entries_.empty();
  }

  std::size_t size() const noexcept {
    return entries_.size();
  }

  std::size_t body_bytes() const noexcept {
    return body_bytes_;
  }

  void clear() {
    entries_.clear();
    lru_.clear();
    body_bytes_ = 0;
  }

  void evict_expired() {
    auto it = entries_.begin();
    while (it != entries_.end()) {
      if (it->second.expires_at.is_in_past()) {
        auto erase_it = it++;
        erase(erase_it);
      } else {
        ++it;
      }
    }
  }

  std::optional<std::string> lookup(const std::string& key) {
    evict_expired();
    auto it = entries_.find(key);
    if (it == entries_.end()) {
      return std::nullopt;
    }
    touch(it);
    return it->second.response_json;
  }

  bool store(const std::string& key, std::string response_json, td::Timestamp expires_at) {
    evict_expired();
    if (max_body_bytes_ > 0 && response_json.size() > max_body_bytes_) {
      return false;
    }
    auto existing = entries_.find(key);
    if (existing != entries_.end()) {
      erase(existing);
    }
    lru_.push_front(key);
    body_bytes_ += response_json.size();
    entries_.emplace(key, Entry{std::move(response_json), expires_at, 0, lru_.begin()});
    auto inserted = entries_.find(key);
    inserted->second.size_bytes = inserted->second.response_json.size();
    evict_to_budget();
    return entries_.find(key) != entries_.end();
  }

 private:
  struct Entry {
    std::string response_json;
    td::Timestamp expires_at;
    std::size_t size_bytes{0};
    std::list<std::string>::iterator lru_it;
  };

  void erase(std::unordered_map<std::string, Entry>::iterator it) {
    body_bytes_ -= it->second.size_bytes;
    lru_.erase(it->second.lru_it);
    entries_.erase(it);
  }

  void touch(std::unordered_map<std::string, Entry>::iterator it) {
    lru_.splice(lru_.begin(), lru_, it->second.lru_it);
  }

  void evict_to_budget() {
    while ((max_entries_ > 0 && entries_.size() > max_entries_) ||
           (max_body_bytes_ > 0 && body_bytes_ > max_body_bytes_)) {
      if (lru_.empty()) {
        break;
      }
      auto it = entries_.find(lru_.back());
      if (it == entries_.end()) {
        lru_.pop_back();
        continue;
      }
      erase(it);
    }
  }

  std::size_t max_entries_{0};
  std::size_t max_body_bytes_{0};
  std::unordered_map<std::string, Entry> entries_;
  std::list<std::string> lru_;
  std::size_t body_bytes_{0};
};

class JsonRpcServer final : public td::actor::Actor, public virtual metrics::AsyncCollector {
 public:
  struct Options {
    bool readonly = false;           // disable sendBoc/sendBocReturnHash/sendQuery/submitSignedTransaction
    std::string cors_origin = "*";   // Access-Control-Allow-Origin value
    td::int32 readyz_threshold = 60; // sync lag threshold in seconds for /readyz
    double request_timeout = 30.0;   // per-request timeout in seconds (0 = no timeout)
    std::string api_key;             // empty = no auth required
    td::int32 cache_ttl = 0;        // seconds, 0 = disabled
    std::size_t cache_max_entries = 1024;
    std::size_t cache_max_body_bytes = 8 << 20;
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

  // Method handlers — account/permission initial surfaces
  void handle_getAccountCapability(td::JsonObject &params, std::string req_id,
                                   td::Promise<HttpReturn> promise);
  void handle_getAccountDelegations(td::JsonObject &params, std::string req_id,
                                    td::Promise<HttpReturn> promise);
  void handle_getAccountSessions(td::JsonObject &params, std::string req_id,
                                 td::Promise<HttpReturn> promise);
  void handle_getAccountAgents(td::JsonObject &params, std::string req_id,
                               td::Promise<HttpReturn> promise);
  void handle_buildTransactionIntent(td::JsonObject &params, std::string req_id,
                                     td::Promise<HttpReturn> promise);
  void handle_getSigningPayload(td::JsonObject &params, std::string req_id,
                                td::Promise<HttpReturn> promise);
  void handle_submitSignedTransaction(td::JsonObject &params, std::string req_id,
                                      td::Promise<HttpReturn> promise);

  // Method handlers — account/permission lifecycle surfaces
  void handle_grantAccountDelegation(td::JsonObject &params, std::string req_id,
                                      td::Promise<HttpReturn> promise);
  void handle_revokeAccountDelegation(td::JsonObject &params, std::string req_id,
                                       td::Promise<HttpReturn> promise);
  void handle_grantAccountSession(td::JsonObject &params, std::string req_id,
                                    td::Promise<HttpReturn> promise);
  void handle_revokeAccountSession(td::JsonObject &params, std::string req_id,
                                     td::Promise<HttpReturn> promise);
  void handle_grantAccountAgent(td::JsonObject &params, std::string req_id,
                                  td::Promise<HttpReturn> promise);
  void handle_revokeAccountAgent(td::JsonObject &params, std::string req_id,
                                   td::Promise<HttpReturn> promise);

  // Delegation reference validation for permission-bearing intents
  void validate_delegation_and_return_intent(
      block::StdAddress addr, std::string addr_str,
      std::string delegation_ref,
      std::string intent_json,
      std::string req_id,
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
  static HttpReturn make_raw_json_response(const std::string& json_body,
                                            const std::string& cors_origin = "*");
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

  JsonRpcResponseCache cache_;

  static const std::set<std::string> &cacheable_methods();

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
