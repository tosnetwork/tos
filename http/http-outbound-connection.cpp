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
#include "td/utils/port/StdStreams.h"

#include "http-outbound-connection.h"

namespace tos {

namespace http {

td::Status HttpOutboundConnection::receive(td::ChainBufferReader &input) {
  if (input.size() == 0) {
    return td::Status::OK();
  }
  if (reading_payload_) {
    return receive_payload(input);
  }
  if (!promise_) {
    return td::Status::Error("unexpected data");
  }

  while (!cur_response_ || !cur_response_->check_parse_header_completed()) {
    bool exit_loop;
    auto R = HttpResponse::parse(std::move(cur_response_), cur_line_, force_no_payload_, keep_alive_, exit_loop, input);
    if (R.is_error()) {
      answer_error(HttpStatusCode::status_bad_request, "", std::move(promise_));
      return td::Status::OK();
    }
    cur_response_ = R.move_as_ok();
    if (exit_loop) {
      return td::Status::OK();
    }
  }

  if (cur_response_->code() == 100) {
    cur_response_ = nullptr;
    return td::Status::OK();
  }

  close_after_read_ = !cur_response_->keep_alive() || !keep_alive_;

  auto payload = cur_response_->create_empty_payload().move_as_ok();
  promise_.set_value(std::make_pair(std::move(cur_response_), payload));
  // Round 156 MEDIUM fix: propagate the initial read_payload result
  // for outbound responses too.  Pre-fix this caller silently dropped
  // the Status, so a malicious upstream that included response
  // headers and an oversize chunk header in the same TCP write
  // tripped the round-152/153 size cap inside HttpPayload::parse,
  // got Status::Error → propagated through read_payload, and was
  // discarded here — leaving the outbound connection in an error
  // state without tearing down at the original reject point.
  // Mirrors the inbound fix in http-inbound-connection.cpp.
  TRY_STATUS(read_payload(std::move(payload)));

  if (!reading_payload_) {
    return td::Status::OK();
  }
  return receive_payload(input);
}

void HttpOutboundConnection::send_query(
    std::unique_ptr<HttpRequest> request, std::shared_ptr<HttpPayload> payload, td::Timestamp timeout,
    td::Promise<std::pair<std::unique_ptr<HttpResponse>, std::shared_ptr<HttpPayload>>> promise) {
  CHECK(request);
  CHECK(payload);
  if (promise_) {
    LOG(INFO) << "delaying send of HTTP request";
    next_.push_back(Query{std::move(request), std::move(payload), timeout, std::move(promise)});
    return;
  }
  LOG(INFO) << "sending HTTP request";
  keep_alive_ = request->keep_alive();
  force_no_payload_ = request->no_payload_in_answer();
  request->store_http(buffered_fd_.output_buffer());
  write_payload(std::move(payload));
  promise_ = std::move(promise);
  alarm_timestamp() = timeout;

  loop();
}

void HttpOutboundConnection::send_next_query() {
  if (next_.size() == 0) {
    return;
  }

  LOG(INFO) << "sending delayed HTTP request";
  auto p = std::move(next_.front());
  next_.pop_front();
  keep_alive_ = p.request->keep_alive();
  force_no_payload_ = p.request->no_payload_in_answer();

  p.request->store_http(buffered_fd_.output_buffer());
  write_payload(std::move(p.payload));
  alarm_timestamp() = p.timeout;
  promise_ = std::move(p.promise);

  loop();
}

}  // namespace http

}  // namespace tos
