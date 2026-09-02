/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2019-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include "http-connection.h"
#include "http-server.h"
#include "http.h"

#include "td/utils/Time.h"
#include "td/utils/port/IPAddress.h"

namespace tos {

namespace http {

class HttpInboundConnection : public HttpConnection {
 public:
  HttpInboundConnection(td::SocketFd fd, std::shared_ptr<HttpServer::Callback> http_callback,
                        HttpServer::AllMetrics metrics, double request_header_timeout = 0,
                        double request_body_timeout = 0)
      : HttpConnection(std::move(fd), nullptr, false)
      , http_callback_(std::move(http_callback))
      , metrics_(std::move(metrics))
      , request_header_timeout_(request_header_timeout)
      , request_body_timeout_(request_body_timeout) {
    metrics_.connections->add(1);
    metrics_.connections_total->add(1);
    // Capture the TCP peer IP exactly once, at accept time. This is the
    // real connecting client (or the operator's reverse proxy) — it is
    // NOT under client control, unlike X-Forwarded-For. Used by the
    // JSON-RPC server's per-IP rate gate via HttpRequest::peer_ip(). On
    // failure (rare: getpeername(2) errors out e.g. on closed sockets),
    // peer_ip_ stays empty and the JSON-RPC layer downgrades to the
    // shared "unknown" bucket.
    td::IPAddress peer;
    // BufferedFd<SocketFd> publicly derives from SocketFd, so this
    // implicitly binds the const SocketFd& parameter.
    auto status = peer.init_peer_address(buffered_fd_);
    if (status.is_ok() && peer.is_valid()) {
      // get_ip_str() uses a thread-local buffer; copy out immediately.
      peer_ip_ = peer.get_ip_str().str();
    }
  }

  ~HttpInboundConnection() override {
    metrics_.connections->sub(1);
  }

  void start_up() override {
    HttpConnection::start_up();
    arm_request_header_deadline();
  }

  // A connection that has not delivered a complete request by the
  // deadline is closed, so that a client trickling bytes (or sending
  // nothing at all) cannot hold the connection open forever — neither in
  // the header phase nor by declaring a body and then withholding it.
  // Bodies with no definite end (tunnels, read-until-close streams) are
  // exempt, as is writing the response; the payload size caps bound those.
  void alarm() override {
    if (request_header_timeout_ <= 0) {
      return;
    }
    if (waiting_for_client_request_data() && request_header_deadline_.is_in_past()) {
      stop();
      return;
    }
    alarm_timestamp() = waiting_for_client_request_data() ? request_header_deadline_
                                                          : td::Timestamp::in(request_header_timeout_);
  }

  td::Status receive_eof() override {
    if (found_eof_) {
      return td::Status::OK();
    }
    found_eof_ = true;
    if (reading_payload_) {
      if (reading_payload_->payload_type() != HttpPayload::PayloadType::pt_eof &&
          reading_payload_->payload_type() != HttpPayload::PayloadType::pt_tunnel) {
        return td::Status::Error("unexpected EOF");
      } else {
        reading_payload_->complete_parse();
        payload_read();
        return td::Status::OK();
      }
    } else {
      if (read_next_request_) {
        stop();
        return td::Status::OK();
      }
      return td::Status::OK();
    }
  }

  void send_client_error();
  void send_server_error();
  void send_proxy_error(td::Status error);

  void payload_written() override {
    writing_payload_ = nullptr;
    if (!close_after_write_) {
      read_next_request_ = true;
      if (found_eof_) {
        stop();
        return;
      }
      arm_request_header_deadline();
    }
  }
  void payload_read() override {
    reading_payload_ = nullptr;
    read_next_request_ = false;
  }

  td::Status receive(td::ChainBufferReader &input) override;
  void send_answer(std::unique_ptr<HttpResponse> response, std::shared_ptr<HttpPayload> payload);

 private:
  static constexpr size_t chunk_size() {
    return 1 << 14;
  }

  bool waiting_for_request_headers() const {
    return read_next_request_ && !reading_payload_ &&
           (!cur_request_ || !cur_request_->check_parse_header_completed());
  }

  // True while progress depends on the client sending more of its request:
  // the header phase, and any request payload. The single exception is a
  // tunnel the handler has explicitly ACCEPTED with a 2xx response — an
  // established tunnel is a long-lived bidirectional stream by design. A
  // tunnel merely requested (a CONNECT whose answer is still pending or was
  // refused) stays under the deadline, otherwise refused CONNECTs would pin
  // connection slots forever.
  bool waiting_for_client_request_data() const {
    if (waiting_for_request_headers()) {
      return true;
    }
    if (reading_payload_) {
      return !(reading_payload_->payload_type() == HttpPayload::PayloadType::pt_tunnel &&
               tunnel_established_);
    }
    return false;
  }

  void arm_request_header_deadline() {
    if (request_header_timeout_ <= 0) {
      return;
    }
    request_header_deadline_ = td::Timestamp::in(request_header_timeout_);
    alarm_timestamp() = request_header_deadline_;
  }

 public:
  // Called when the headers of a request completed and a definite-end body
  // is about to be read: the body gets its own, typically longer, window so
  // a legitimate slow uploader is not held to the header deadline while a
  // withheld body still cannot pin the connection.
  void arm_request_body_deadline() {
    if (request_header_timeout_ <= 0) {
      return;
    }
    double timeout = request_body_timeout_ > 0 ? request_body_timeout_ : request_header_timeout_;
    request_header_deadline_ = td::Timestamp::in(timeout);
    alarm_timestamp() = request_header_deadline_;
  }

 private:

  bool read_next_request_ = true;

  std::shared_ptr<HttpServer::Callback> http_callback_;
  std::unique_ptr<HttpRequest> cur_request_;
  std::string cur_line_;
  // Real TCP peer IP address (numeric textual form). Captured exactly
  // once at accept time and copied onto every parsed HttpRequest before
  // it is dispatched to the upper-layer callback. Empty when
  // init_peer_address() failed at construction time.
  std::string peer_ip_;

  HttpServer::AllMetrics metrics_;
  double request_header_timeout_ = 0;
  double request_body_timeout_ = 0;
  td::Timestamp request_header_deadline_;
  // Set when the handler answers a CONNECT with a 2xx response; only then
  // is the tunnel payload exempt from the request deadline.
  bool tunnel_established_ = false;
};

}  // namespace http

}  // namespace tos
