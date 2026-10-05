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
                        double request_body_timeout = 0, bool reject_request_bodies = false, size_t io_buffer_bytes = 0,
                        double response_timeout = 0, bool close_after_early_answer = false,
                        std::shared_ptr<BodyBudget> body_budget = nullptr)
      : HttpConnection(std::move(fd), nullptr, false, io_buffer_bytes)
      , http_callback_(std::move(http_callback))
      , metrics_(std::move(metrics))
      , request_header_timeout_(request_header_timeout)
      , request_body_timeout_(request_body_timeout)
      , reject_request_bodies_(reject_request_bodies)
      , response_timeout_(response_timeout)
      , close_after_early_answer_(close_after_early_answer)
      , body_budget_(std::move(body_budget)) {
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
    if (body_budget_) {
      body_budget_->sub_read_ahead(counted_read_ahead_);
    }
  }

  // Socket input a connection may buffer while its current request has not
  // been admitted: enough for the largest request line plus header block the
  // parser accepts (HttpRequest::max_one_header_size() +
  // HttpRequest::max_header_size()), with room to spare. Bytes of a body that
  // arrive with the headers can sit in this window unparsed; they are not
  // charged to the listener's body reservation, so this is the bound on
  // uncharged input per connection, and the listener's connection limit times
  // this is the bound across it (tracked in BodyBudget::read_ahead()).
  static constexpr size_t header_read_ahead() {
    return 64 << 10;
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
  // exempt. A listener can separately bound the response writing phase.
  void alarm() override {
    if (response_pending_) {
      if (writing_payload_ || buffered_fd_.ready_for_flush_write() != 0) {
        if (response_deadline_.is_in_past()) {
          stop();
          return;
        }
        alarm_timestamp() = response_deadline_;
        return;
      }
      response_pending_ = false;
    }
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
    if (admission_pending_) {
      // Decided once the admission answer arrives: a bodiless request is
      // still answered, a request whose body was cut off fails then.
      deferred_eof_ = true;
      return td::Status::OK();
    }
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
  void send_payload_refused();
  void send_server_error();
  void send_proxy_error(td::Status error);
  // True when this listener closes after an answer given while the request
  // body is still being read (see HttpServer::Limits::close_after_early_answer).
  bool answering_before_body_read() const {
    return close_after_early_answer_ && reading_payload_ && !tunnel_established_;
  }
  void send_bodiless_error(td::Slice status_line);

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
    body_window_ = 0;
  }

  td::Status receive(td::ChainBufferReader &input) override;
  void send_answer(std::unique_ptr<HttpResponse> response, std::shared_ptr<HttpPayload> payload);
  // The header admission answer for the request held in cur_request_.
  void on_admission(td::Result<HttpServer::Admission> result);

 protected:
  void loop() override {
    HttpConnection::loop();
    account_read_ahead();
  }

  // Until a request is admitted only the header read-ahead is read off the
  // socket. While an admitted body is read with a listener reservation, the
  // window is the part of that reservation not yet parsed out of the input,
  // plus the read-ahead for whatever follows the body.
  size_t input_window() override {
    if (reading_payload_ && !admission_pending_) {
      if (!body_budget_) {
        return io_window();
      }
      return header_read_ahead() + body_window_;
    }
    return header_read_ahead();
  }

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
    // A request awaiting admission is held to the header deadline too, so an
    // admission that never answers cannot pin the connection.
    if (admission_pending_ || waiting_for_request_headers()) {
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
    alarm_timestamp() = response_pending_ && response_deadline_.at() < request_header_deadline_.at()
                            ? response_deadline_
                            : request_header_deadline_;
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
    alarm_timestamp() = response_pending_ && response_deadline_.at() < request_header_deadline_.at()
                            ? response_deadline_
                            : request_header_deadline_;
  }

 private:
  // The deadline is absolute and starts when a response is queued. Writing
  // part of it never moves the deadline. A response queued while an earlier
  // one still has bytes waiting for the socket inherits the earlier deadline,
  // so a client that keeps sending requests without reading cannot push the
  // deadline of output it has never read further out.
  void arm_response_deadline() {
    if (response_timeout_ > 0) {
      bool earlier_output_pending =
          response_pending_ && (writing_payload_ || buffered_fd_.ready_for_flush_write() != 0);
      response_pending_ = true;
      if (!earlier_output_pending) {
        response_deadline_ = td::Timestamp::in(response_timeout_);
      }
      alarm_timestamp() = response_deadline_;
    }
  }

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
  bool reject_request_bodies_ = false;
  double response_timeout_ = 0;
  bool close_after_early_answer_ = false;
  bool response_pending_ = false;
  td::Timestamp response_deadline_;
  td::Timestamp request_header_deadline_;
  // Set when the handler answers a CONNECT with a 2xx response; only then
  // is the tunnel payload exempt from the request deadline.
  bool tunnel_established_ = false;

  void send_body_capacity_refused();
  // Reserves and starts reading the admitted request's body; false when the
  // request was refused instead or the connection is closing.
  bool start_admitted_request();
  // Input ended while a request awaited admission.
  bool deferred_eof_ = false;
  // Updates the listener's read-ahead count with the input this connection
  // holds beyond what its current reservation covers.
  void account_read_ahead() {
    if (!body_budget_) {
      return;
    }
    size_t unread = buffered_fd_.left_unread();
    size_t uncharged = unread > body_window_ ? unread - body_window_ : 0;
    if (uncharged > counted_read_ahead_) {
      body_budget_->add_read_ahead(uncharged - counted_read_ahead_);
    } else if (uncharged < counted_read_ahead_) {
      body_budget_->sub_read_ahead(counted_read_ahead_ - uncharged);
    }
    counted_read_ahead_ = uncharged;
  }

  std::shared_ptr<BodyBudget> body_budget_;
  // True from the moment complete headers are handed to admit_request until
  // the admission answer arrives.
  bool admission_pending_ = false;
  // Bytes of the current body reservation not yet parsed out of the input.
  size_t body_window_ = 0;
  size_t counted_read_ahead_ = 0;
};

}  // namespace http

}  // namespace tos
