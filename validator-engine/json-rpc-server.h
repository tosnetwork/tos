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
#include <optional>

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
    std::size_t max_connections = 1024;    // simultaneously open HTTP connections (0 = unlimited)
    double request_header_timeout = 30.0;  // seconds to deliver request headers (0 = no deadline)
    std::string api_key;             // empty = no auth required
    td::int32 cache_ttl = 0;        // seconds, 0 = disabled
    std::size_t cache_max_entries = 1024;
    std::size_t cache_max_body_bytes = 8 << 20;
    // M-01 hardening: control how the per-IP rate gate attributes a
    // request to a source IP.
    //
    // When `trust_proxy_headers` is false (the default), the gate is
    // keyed strictly off the real TCP peer IP captured by the inbound
    // HTTP connection. Direct clients cannot bypass the gate by
    // forging `X-Forwarded-For` / `X-Real-IP`, and a public RPC
    // listener with no upstream proxy still buckets every direct
    // client correctly. Empty peer IPs (rare; init_peer_address(2)
    // failed) are bucketed into a shared "unknown" slot rather than
    // falling through with no attribution.
    //
    // When `trust_proxy_headers` is true, the gate honours the
    // leftmost `X-Forwarded-For` (or `X-Real-IP` fallback) header ONLY
    // when the real TCP peer is on the loopback interface or appears
    // in `trusted_proxies`. This is the documented deployment for an
    // operator-controlled reverse proxy that terminates TLS and
    // injects the original client IP. Outside that allow-list the
    // headers are ignored — a malicious direct client cannot
    // self-stamp `X-Forwarded-For` to rotate buckets.
    bool trust_proxy_headers = false;
    // Optional explicit allow-list of trusted proxy IPs. Loopback
    // addresses (127.0.0.1, ::1) are always implicit. Each entry is a
    // single IPv4 / IPv6 address in textual form; CIDR ranges are not
    // accepted (operators are expected to know the exact peer address
    // of their reverse proxy).
    std::vector<std::string> trusted_proxies;
  };

  // M-02 hardening: the listen-time decision matrix is broken out so
  // unit tests can drive every (loopback, profile, api_key, override)
  // tuple without standing up a real TCP listener. Returns the result
  // type below; `listen()` itself only translates `Refuse*` outcomes
  // into the appropriate LOG(ERROR) + early return.
  enum class ListenDecision {
    Accept,
    RefuseWriteRemoteWithoutAuth,
  };
  // Pure decision-making helper. No side effects, no logging.
  // - `is_loopback`     : true iff the listening address is 127.0.0.1 / ::1.
  // - `api_key_empty`   : `Options::api_key.empty()` snapshot.
  // - `readonly`        : `Options::readonly` snapshot.
  static ListenDecision decide_listen_admission(
      bool is_loopback,
      bool api_key_empty,
      bool readonly);

  // M-01 hardening: pure helper that maps a real TCP peer IP plus
  // optional X-Forwarded-For / X-Real-IP header values onto the
  // attribution string consumed by the per-IP rate gate.
  //
  // Behaviour:
  //   - If `trust_proxy_headers` is false, the leftmost forwarded /
  //     real-IP header values are ignored; the function returns the
  //     real TCP peer IP, or "unknown" when that is empty.
  //   - If `trust_proxy_headers` is true, the headers are honoured
  //     ONLY when `peer_ip` is loopback (127.0.0.1, ::1, 0:0:0:0:0:0:0:1)
  //     or appears verbatim in `trusted_proxies`. The leftmost token
  //     of `forwarded_for` (CSV) wins; if it is empty, `real_ip` is
  //     used as a fallback. When neither header is present the
  //     function falls back to the peer IP itself.
  //   - The returned string is guaranteed to be non-empty: an empty
  //     peer with no usable header value is returned as "unknown" so
  //     the per-IP gate never falls through to the empty-string
  //     bypass branch.
  static std::string resolve_source_ip(
      const std::string& peer_ip,
      const std::string& forwarded_for,
      const std::string& real_ip,
      bool trust_proxy_headers,
      const std::vector<std::string>& trusted_proxies);

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
  // `source_ip` is the attribution string passed by value to the actor
  // scheduler. Empty string means the client address was not available.
  void on_body_ready(PayloadPtr payload, std::string source_ip,
                     td::Promise<HttpReturn> promise);
  void process_body(td::BufferSlice body, std::string req_id,
                    std::string source_ip,
                    td::Promise<HttpReturn> promise);
  // JSON-RPC 2.0 single object dispatch: parses id/method/params from `req`
  // and dispatches.  `req` must be a JSON Object — callers (process_body and
  // the batch handler) enforce this.
  void process_single_object_request(td::JsonValue req,
                                     std::string source_ip,
                                     td::Promise<HttpReturn> promise);
  // JSON-RPC 2.0 batch dispatch: array of element requests becomes an array
  // of element responses (notifications omitted).  See process_batch.
  struct BatchState;
  void process_batch(std::vector<td::JsonValue> elements,
                     std::string source_ip,
                     td::Promise<HttpReturn> promise);
  void process_batch_step(std::shared_ptr<BatchState> state);
  void finalize_batch(std::shared_ptr<BatchState> state);
  void process_rest_post_body(td::BufferSlice body, std::string method,
                              std::string source_ip,
                              td::Promise<HttpReturn> promise);
  // Called by PostRestWaiter via actor message — reads payload OUTSIDE mutex.
  void on_post_rest_body_ready(PayloadPtr payload, std::string method,
                               std::string source_ip,
                               td::Promise<HttpReturn> promise);
  void dispatch_method(std::string method, td::JsonObject &params,
                       std::string req_id, std::string source_ip,
                       td::Promise<HttpReturn> promise);
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

  // wc=0 in-process wallet index (see https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-wc0-wallet-index.md)
  void handle_getAccountJettons(td::JsonObject &params, std::string req_id,
                                td::Promise<HttpReturn> promise);
  void handle_getAccountNfts(td::JsonObject &params, std::string req_id,
                             td::Promise<HttpReturn> promise);
  void handle_getAccountEvents(td::JsonObject &params, std::string req_id,
                               td::Promise<HttpReturn> promise);
  void handle_getAccountEvent(td::JsonObject &params, std::string req_id,
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

  // Method handlers — new APIs (HTTP API parity)
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
  //
  // Every call site that omits the
  // explicit `cors_origin` argument silently falls back to "*", which
  // bypasses an operator-configured restrictive CORS origin. Of the 478
  // response sites in `json-rpc-server*.cpp`, 474 currently omit the
  // argument. Threading `opts_.cors_origin` through them all is purely
  // mechanical and should be handled as a focused follow-up;
  // until that migration lands, deployments that depend on a restrictive
  // `cors_origin` setting MUST treat this server's responses as
  // potentially world-readable from any browser origin. Track the
  // migration as a follow-up rather than relying on these defaults.
  static HttpReturn make_raw_json_response(const std::string& json_body,
                                            const std::string& cors_origin = "*");
  static HttpReturn make_json_ok(std::string result_json, std::string id,
                                 const std::string& cors_origin = "*");
  static HttpReturn make_json_error(int code, std::string message, std::string id,
                                    const std::string& cors_origin = "*");
  // Standards-compliant JSON-RPC 2.0 error (nested `error:{code,message}`,
  // HTTP 200). `make_json_error` is retained for TVM JSON-RPC methods
  // whose existing tests depend on `{ok, error:<string>, code}` at
  // top level and on mapped HTTP status codes.
  static HttpReturn make_json_rpc_error(int code, std::string message, std::string id,
                                        const std::string& cors_origin = "*");
  // HTTP 204 No Content with CORS — used for batch-of-only-notifications.
  static HttpReturn make_no_content(const std::string& cors_origin = "*");
  // HTTP 200 wrapping a literal JSON body (e.g. a JSON array of batch
  // element responses).  Identical to make_raw_json_response but with an
  // explicit name to clarify intent at call sites.
  static HttpReturn make_json_array_response(std::string body,
                                              const std::string& cors_origin = "*");
  // Extract the response body bytes from an HttpReturn.  Consumes the
  // payload — caller must not use `ret.second` afterwards.
  static std::string extract_response_body(HttpReturn& ret);
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

  // Returns true iff `method` mutates chain state via this server. Centralized
  // so `opts_.readonly` can be enforced once before fast-path dispatch.
  // Adding a new write method? Add it here.
  static bool is_write_method(const std::string &method);

  // Cache-aware dispatch: checks cache for read-only methods, delegates to
  // dispatch_method() on miss, and stores successful results.
  // `source_ip` flows through to `dispatch_method`. Cache hits return
  // without additional admission checks because cached responses cost
  // essentially nothing.
  void cached_dispatch_method(std::string method, td::JsonObject &params,
                              std::string req_id, std::string source_ip,
                              td::Promise<HttpReturn> promise);

  void alarm() override;

  static const std::set<std::string> &cacheable_methods();

  td::actor::ActorId<validator::ValidatorManagerInterface> validator_manager_;
  td::actor::ActorOwn<http::HttpServer> http_;
  Options opts_;
  JsonRpcResponseCache cache_;
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
