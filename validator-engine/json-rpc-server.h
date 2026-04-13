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
#include "td/actor/actor.h"
#include "td/utils/JsonBuilder.h"
#include "validator/validator.h"

namespace tos {

class JsonRpcServer final : public td::actor::Actor {
 public:
  struct Options {
    bool readonly = false;           // disable sendBoc/sendBocReturnHash/sendQuery
    std::string cors_origin = "*";   // Access-Control-Allow-Origin value
    td::int32 readyz_threshold = 60; // sync lag threshold in seconds for /readyz
  };

  static td::actor::ActorOwn<JsonRpcServer> create(
      td::actor::ActorId<validator::ValidatorManagerInterface> validator_manager,
      Options options);

  void listen(td::IPAddress addr);

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
  void process_body(td::BufferSlice body, std::string req_id,
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

  // Method handlers — send family
  void handle_sendBocReturnHash(td::JsonObject &params, std::string req_id,
                                td::Promise<HttpReturn> promise);
  void handle_sendQuery(td::JsonObject &params, std::string req_id,
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

  td::actor::ActorId<validator::ValidatorManagerInterface> validator_manager_;
  td::actor::ActorOwn<http::HttpServer> http_;
  Options opts_;
};

}  // namespace tos
