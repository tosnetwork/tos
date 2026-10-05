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

#include <atomic>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "auto/tl/tos_api.h"
#include "td/actor/PromiseFuture.h"
#include "td/utils/buffer.h"

namespace tos {

namespace http {

enum HttpStatusCode : td::uint32 {
  status_ok = 200,
  status_bad_request = 400,
  status_method_not_allowed = 405,
  status_internal_server_error = 500,
  status_bad_gateway = 502,
  status_service_unavailable = 503,
  status_gateway_timeout = 504
};

struct HttpHeader {
  std::string name;
  std::string value;
  void store_http(td::ChainBufferWriter &output);
  tl_object_ptr<tos_api::http_header> store_tl();

  size_t size() const {
    return 2 + name.size() + value.size();
  }
  bool empty() const {
    return name.size() == 0;
  }

  td::Status basic_check();
};

namespace util {

td::Result<std::string> get_line(td::ChainBufferReader &input, std::string &cur_line, bool &read, size_t max_line_size);
td::Result<HttpHeader> get_header(std::string line);

}  // namespace util

// The request-body capacity one listener shares among all its connections.
// A connection reserves a request's body before it parses any of it and the
// reservation travels with the body to whoever consumes it, so the bytes held
// for request bodies across the listener never exceed the capacity, whether
// they sit in a connection, in a payload, or in the consumer's copy.
//
// It also counts, separately, the socket read-ahead of connections whose
// current request has not been admitted (see HttpInboundConnection): bytes
// read while looking for the end of the request headers, which may include
// the start of a body that is not charged to any reservation.
class BodyBudget : public std::enable_shared_from_this<BodyBudget> {
 public:
  // Bytes of one request body; released when destroyed.
  class Reservation {
   public:
    Reservation(std::shared_ptr<BodyBudget> budget, size_t bytes) : budget_(std::move(budget)), bytes_(bytes) {
    }
    Reservation(const Reservation &) = delete;
    Reservation &operator=(const Reservation &) = delete;
    ~Reservation() {
      if (budget_) {
        budget_->release(bytes_);
      }
    }
    size_t bytes() const {
      return bytes_;
    }

   private:
    std::shared_ptr<BodyBudget> budget_;
    size_t bytes_;
  };

  explicit BodyBudget(size_t capacity) : capacity_(capacity) {
  }

  // Reserves `bytes`, or returns null when they do not fit in what is left.
  std::shared_ptr<Reservation> reserve(size_t bytes) {
    size_t current = reserved_.load(std::memory_order_relaxed);
    while (true) {
      if (bytes > capacity_ || current > capacity_ - bytes) {
        return nullptr;
      }
      if (reserved_.compare_exchange_weak(current, current + bytes, std::memory_order_acq_rel)) {
        return std::make_shared<Reservation>(shared_from_this(), bytes);
      }
    }
  }

  size_t capacity() const {
    return capacity_;
  }
  size_t reserved() const {
    return reserved_.load(std::memory_order_acquire);
  }

  // Read-ahead accounting, updated by each connection as its unadmitted
  // input grows and shrinks.
  void add_read_ahead(size_t bytes) {
    read_ahead_.fetch_add(bytes, std::memory_order_acq_rel);
  }
  void sub_read_ahead(size_t bytes) {
    size_t current = read_ahead_.load(std::memory_order_relaxed);
    while (!read_ahead_.compare_exchange_weak(current, current >= bytes ? current - bytes : 0,
                                              std::memory_order_acq_rel)) {
    }
  }
  size_t read_ahead() const {
    return read_ahead_.load(std::memory_order_acquire);
  }

 private:
  void release(size_t bytes) {
    size_t current = reserved_.load(std::memory_order_relaxed);
    while (
        !reserved_.compare_exchange_weak(current, current >= bytes ? current - bytes : 0, std::memory_order_acq_rel)) {
    }
  }

  const size_t capacity_;
  std::atomic<size_t> reserved_{0};
  std::atomic<size_t> read_ahead_{0};
};

class HttpPayload {
 public:
  enum class PayloadType { pt_empty, pt_eof, pt_chunked, pt_content_length, pt_tunnel };
  HttpPayload(PayloadType t, size_t low_watermark, size_t high_watermark, td::uint64 size)
      : type_(t), low_watermark_(low_watermark), high_watermark_(high_watermark), cur_chunk_size_(size) {
    CHECK(t == PayloadType::pt_content_length);
    state_ = ParseState::reading_chunk_data;
  }
  HttpPayload(PayloadType t, size_t low_watermark, size_t high_watermark)
      : type_(t), low_watermark_(low_watermark), high_watermark_(high_watermark) {
    CHECK(t != PayloadType::pt_content_length);
    CHECK(t != PayloadType::pt_empty);
    switch (t) {
      case PayloadType::pt_eof:
      case PayloadType::pt_tunnel:
        state_ = ParseState::reading_chunk_data;
        break;
      case PayloadType::pt_chunked:
        state_ = ParseState::reading_chunk_header;
        break;
      default:
        UNREACHABLE();
    }
  }
  HttpPayload(PayloadType t) : type_(t) {
    CHECK(t == PayloadType::pt_empty);
    state_ = ParseState::completed;
    written_zero_chunk_ = true;
    written_trailer_ = true;
  }

  class Callback {
   public:
    virtual void run(size_t ready_bytes) = 0;
    virtual void completed() = 0;
    virtual void flush() {
    }
    virtual ~Callback() = default;
  };
  void add_callback(std::unique_ptr<Callback> callback);
  void run_callbacks();
  void run_callbacks(std::vector<Callback *> callbacks, bool completed, size_t ready_bytes);

  td::Status parse(td::ChainBufferReader &input);
  bool parse_completed() const;
  void complete_parse();
  size_t ready_bytes() const {
    return ready_bytes_;
  }
  bool low_watermark_reached() const {
    return ready_bytes_ <= low_watermark_;
  }
  bool high_watermark_reached() const {
    return ready_bytes_ > high_watermark_;
  }
  bool is_error() const {
    return error_.load(std::memory_order_acquire);
  }
  // The payload will not be completed: mark it failed and tell its consumers,
  // once, as completion would, so they see is_error() instead of waiting. A
  // consumer added later is told when it is added. Completion and failure
  // exclude each other: whichever comes first is the payload's end, and a
  // failed payload accepts no more input.
  void fail();
  PayloadType payload_type() const {
    return type_;
  }
  td::MutableSlice get_read_slice();
  void confirm_read(size_t s);
  void add_trailer(HttpHeader header);
  void add_chunk(td::BufferSlice data);
  td::BufferSlice get_slice(size_t max_size);
  void slice_gc();
  HttpHeader get_header();

  bool store_http(td::ChainBufferWriter &output, size_t max_size, HttpPayload::PayloadType store_type);
  tl_object_ptr<tos_api::http_payloadPart> store_tl(size_t max_size);

  bool written() const {
    return ready_bytes_ == 0 && parse_completed() && written_zero_chunk_ && written_trailer_;
  }

  void flush();

  bool is_flushing() const {
    return is_flushing_;
  }

  void set_flushed() {
    is_flushing_ = false;
  }

  // The listener's reservation for this body. It is held by the payload
  // while the body is read and buffered; a consumer that keeps the body, or a
  // copy of it, past the payload takes it over with take_reservation() and
  // holds it until it is done with the body.
  void attach_reservation(std::shared_ptr<BodyBudget::Reservation> reservation) {
    std::lock_guard<std::mutex> guard(reservation_mutex_);
    reservation_ = std::move(reservation);
  }
  std::shared_ptr<BodyBudget::Reservation> take_reservation() {
    std::lock_guard<std::mutex> guard(reservation_mutex_);
    return std::move(reservation_);
  }

 private:
  enum class ParseState { reading_chunk_header, reading_chunk_data, reading_trailer, reading_crlf, completed };
  PayloadType type_{PayloadType::pt_chunked};
  size_t low_watermark_;
  size_t high_watermark_;
  std::string tmp_;
  std::list<td::BufferSlice> chunks_;
  std::list<HttpHeader> trailer_;
  size_t trailer_size_ = 0;
  size_t ready_bytes_ = 0;
  td::uint64 cur_chunk_size_ = 0;
  size_t last_chunk_free_ = 0;
  size_t chunk_size_ = 1 << 14;
  bool written_zero_chunk_ = false;
  bool written_trailer_ = false;
  std::atomic<bool> error_{false};
  bool is_flushing_ = false;

  std::list<std::unique_ptr<Callback>> callbacks_;
  bool callbacks_completed_notified_ = false;

  std::atomic<ParseState> state_{ParseState::reading_chunk_header};
  std::mutex mutex_;

  std::mutex reservation_mutex_;
  std::shared_ptr<BodyBudget::Reservation> reservation_;
};

class HttpRequest {
 public:
  static constexpr size_t max_header_size() {
    return 16 << 10;
  }

  static constexpr size_t max_one_header_size() {
    return 16 << 10;
  }

  // Aggregate size of the request line and all header lines accepted so
  // far. Each line is individually capped, but without an aggregate budget
  // a client could stream an unbounded number of short headers for the
  // whole request-header window; parse() enforces max_header_size() here.
  size_t total_headers_size_ = 0;

  // Request body limit: 4 MiB. An earlier revision cut this to 1 MiB, reasoning
  // that the largest payload any method accepts is a 64 KiB bag of cells -- but
  // that 64 KiB bound is on a single base64-decoded BOC on the send path, not
  // on a whole request. runGetMethod takes up to 256 stack cell/slice arguments
  // and the JSON-RPC batch entry takes up to 100 elements, so requests that are
  // well-formed under those existing limits and fit within 4 MiB (a
  // runGetMethod with a handful of ~80 KiB-base64 cells, or a batch of them)
  // exceeded 1 MiB and were rejected -- a compatibility regression, not a dead
  // config. This is also the general HTTP request limit, shared by the RLDP
  // HTTP proxy, so the same reduction broke proxied uploads in (1 MiB, 4 MiB].
  // The 4 MiB receive capacity is kept; giving the JSON-RPC layer a smaller
  // memory budget would need its own limit, separate from this shared one, plus
  // a client batching/argument-budget contract -- not a blanket narrowing here.
  //
  // The Content-Length gate in HttpRequest::add_header stays: it rejects an
  // oversized request before a body is read, rather than letting the reader
  // stall against the watermark with nothing to drain it.
  static constexpr size_t max_payload_size() {
    return 4 << 20;  // 4 MiB
  }

  static constexpr size_t low_watermark() {
    return 1 << 16;  // 64 KiB
  }
  // Must equal max_payload_size(). The JSON-RPC consumer drains a request
  // body only once it has fully arrived, so the reader must be allowed to
  // buffer the whole declared maximum before it pauses here -- otherwise a
  // body between the watermark and the Content-Length limit stalls the
  // reader against a consumer that is waiting for the reader, the exact
  // connection-pinning deadlock the Content-Length gate exists to prevent.
  // Keeping the two equal makes the gate's threshold and the stall point
  // coincide: every body the gate admits can be read to completion.
  static constexpr size_t high_watermark() {
    return 4 << 20;  // 4 MiB, == max_payload_size()
  }

  static td::Result<std::unique_ptr<HttpRequest>> create(std::string method, std::string url,
                                                         std::string proto_version);
  // Rebuild a request from its TL wire form (the inverse of store_tl). Every
  // header is admitted through add_header, so the Content-Length gate applies
  // to the RLDP-proxied path exactly as it does to the socket path. Used by the
  // RLDP HTTP proxy; a malformed or oversized header fails here rather than
  // being silently dropped.
  static td::Result<std::unique_ptr<HttpRequest>> create(const tos_api::http_request &f);

  HttpRequest(std::string method, std::string url, std::string proto_version);

  bool check_parse_header_completed() const;
  bool keep_alive() const {
    return keep_alive_;
  }

  td::Status complete_parse_header();
  td::Status add_header(HttpHeader header);
  td::Result<std::shared_ptr<HttpPayload>> create_empty_payload();
  bool need_payload() const;
  // A body is announced by a non-zero Content-Length or any Transfer-Encoding;
  // "Content-Length: 0" announces nothing and is not a body.
  bool announces_body() const {
    return found_transfer_encoding_ || (found_content_length_ && content_length_ > 0);
  }
  // Bytes to reserve for this request's body before reading it: the declared
  // Content-Length (already capped at max_payload_size() by add_header), the
  // whole max_payload_size() for a chunked body whose size is not known in
  // advance, and nothing for a request without a body.
  size_t body_reservation_bytes() const {
    if (found_content_length_) {
      return content_length_;
    }
    if (found_transfer_encoding_) {
      return max_payload_size();
    }
    return 0;
  }

  const auto &method() const {
    return method_;
  }
  const auto &url() const {
    return url_;
  }
  const auto &proto_version() const {
    return proto_version_;
  }
  const auto &host() const {
    return host_;
  }

  bool no_payload_in_answer() const {
    return method_ == "HEAD";
  }

  // Lookup a request header by name (case-insensitive).
  // Returns empty string if the header is not present.
  std::string get_header(const std::string &name) const {
    for (auto &h : options_) {
      if (h.name.size() == name.size()) {
        bool match = true;
        for (size_t i = 0; i < name.size(); i++) {
          if (std::tolower(static_cast<unsigned char>(h.name[i])) !=
              std::tolower(static_cast<unsigned char>(name[i]))) {
            match = false;
            break;
          }
        }
        if (match) return h.value;
      }
    }
    return {};
  }

  void set_keep_alive(bool value) {
    keep_alive_ = value;
  }

  // Real TCP peer IP address (numeric textual form), captured by the
  // inbound HTTP connection at accept time. Empty when the connection
  // does not have a peer (synthetic / parser-only paths). Distinct from
  // the X-Forwarded-For / X-Real-IP request headers, which are
  // user-controlled and may be forged by a direct client.
  const std::string &peer_ip() const {
    return peer_ip_;
  }
  void set_peer_ip(std::string ip) {
    peer_ip_ = std::move(ip);
  }

  void store_http(td::ChainBufferWriter &output);
  tl_object_ptr<tos_api::http_request> store_tl(td::Bits256 req_id);

  static td::Result<std::unique_ptr<HttpRequest>> parse(std::unique_ptr<HttpRequest> request, std::string &cur_line,
                                                        bool &exit_loop, td::ChainBufferReader &input);

 private:
  std::string method_;
  std::string url_;
  std::string proto_version_;

  std::string host_;
  size_t content_length_ = 0;
  bool found_content_length_ = false;
  bool found_transfer_encoding_ = false;

  bool parse_header_completed_ = false;
  bool keep_alive_ = false;

  std::vector<HttpHeader> options_;
  std::string peer_ip_;
};

// The Content-Length gate admits bodies up to max_payload_size, and the
// reader can buffer up to high_watermark before it pauses for the
// consumer; if the gate admitted more than the reader can hold, a body in
// the gap would stall forever. Keeping them equal is what prevents that.
static_assert(HttpRequest::high_watermark() == HttpRequest::max_payload_size(),
              "request high watermark must equal max payload, or admitted bodies can stall the reader");

class HttpResponse {
 public:
  static constexpr size_t max_header_size() {
    return 16 << 10;
  }

  static constexpr size_t max_one_header_size() {
    return 16 << 10;
  }

  static constexpr size_t max_payload_size() {
    return 1 << 20;
  }

  static constexpr size_t low_watermark() {
    return 1 << 14;
  }
  static constexpr size_t high_watermark() {
    return 1 << 17;
  }

  static td::Result<std::unique_ptr<HttpResponse>> create(std::string proto_version, td::uint32 code,
                                                          std::string reason, bool force_no_payload, bool keep_alive,
                                                          bool is_tunnel = false);

  HttpResponse(std::string proto_version, td::uint32 code, std::string reason, bool force_no_payload, bool keep_alive,
               bool is_tunnel = false);

  bool check_parse_header_completed() const;
  bool keep_alive() const {
    return !force_no_payload_ && keep_alive_;
  }

  td::Status complete_parse_header();
  td::Status add_header(HttpHeader header);
  td::Result<std::shared_ptr<HttpPayload>> create_empty_payload();
  bool need_payload() const;

  auto code() const {
    return code_;
  }
  const auto &proto_version() const {
    return proto_version_;
  }
  void set_keep_alive(bool value) {
    keep_alive_ = value;
  }

  void store_http(td::ChainBufferWriter &output);
  tl_object_ptr<tos_api::http_response> store_tl();

  static td::Result<std::unique_ptr<HttpResponse>> parse(std::unique_ptr<HttpResponse> request, std::string &cur_line,
                                                         bool force_no_payload, bool keep_alive, bool &exit_loop,
                                                         td::ChainBufferReader &input);

  static std::unique_ptr<HttpResponse> create_error(HttpStatusCode code, std::string reason);

  bool found_transfer_encoding() const {
    return found_transfer_encoding_;
  }
  bool found_content_length() const {
    return found_content_length_;
  }

 private:
  std::string proto_version_;
  td::uint32 code_;
  std::string reason_;

  bool force_no_payload_ = false;
  bool force_no_keep_alive_ = false;

  size_t content_length_ = 0;
  bool found_content_length_ = false;
  bool found_transfer_encoding_ = false;

  bool parse_header_completed_ = false;
  bool keep_alive_ = false;
  // Running total of header bytes, capped in parse() the same way the
  // request side is; a server cannot stream headers without bound.
  size_t total_headers_size_ = 0;

  std::vector<HttpHeader> options_;
  bool is_tunnel_ = false;
};

void answer_error(HttpStatusCode code, std::string reason,
                  td::Promise<std::pair<std::unique_ptr<HttpResponse>, std::shared_ptr<HttpPayload>>> promise);

}  // namespace http

}  // namespace tos
