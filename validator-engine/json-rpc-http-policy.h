/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

// The transport policy of the JSON-RPC listener, kept free of the server's
// actor and chain dependencies so a test can run it through a real HttpServer
// (see test/test-json-rpc-http-policy.cpp). JsonRpcServer uses these and only
// these to configure its listener and to refuse unauthenticated requests.

#include <memory>
#include <string>
#include <utility>

#include "http/http-server.h"
#include "http/http.h"

namespace tos::json_rpc {

// Seconds a response may take to be written before the connection is dropped.
// Without it a client that stops reading holds its connection, and every byte
// queued for it, for as long as it likes.
inline constexpr double kDefaultResponseTimeout = 60.0;

inline http::HttpServer::Limits listener_limits(std::size_t max_connections, double request_header_timeout,
                                                double request_body_timeout, double response_timeout) {
  http::HttpServer::Limits limits;
  limits.max_connections = max_connections;
  limits.request_header_timeout = request_header_timeout;
  limits.request_body_timeout = request_body_timeout;
  limits.response_timeout = response_timeout;
  return limits;
}

// The answer to a request whose API key is missing or wrong. It is given from
// the request headers, before the body is read, and it closes the connection
// once written, so a refused client cannot make the server go on reading and
// buffering a body of up to the payload limit.
inline std::pair<std::unique_ptr<http::HttpResponse>, std::shared_ptr<http::HttpPayload>> unauthorized_response(
    const std::string& cors_origin) {
  std::string body =
      "{\"ok\":false,\"jsonrpc\":\"2.0\",\"id\":null,"
      "\"error\":\"Unauthorized: invalid or missing API key\",\"code\":-32000}";

  auto response = http::HttpResponse::create("HTTP/1.1", 401, "Unauthorized", false, false).move_as_ok();
  response->add_header({"Content-Type", "application/json"});
  if (!cors_origin.empty()) {
    response->add_header({"Access-Control-Allow-Origin", cors_origin});
  }
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->complete_parse_header();
  response->set_close_after_write();

  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice(body));
  payload->complete_parse();
  return {std::move(response), std::move(payload)};
}

}  // namespace tos::json_rpc
