/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include "auto/tl/tos_api_json.h"
#include "http/http-client.h"
#include "td/utils/filesystem.h"
#include "td/utils/tl_helpers.h"

#include "service-common.h"

namespace tos::services {
std::atomic<bool> stop_requested{false};
static_assert(std::atomic<bool>::is_always_lock_free);
void request_stop(int) {
  stop_requested.store(true, std::memory_order_relaxed);
}

td::Result<std::vector<liteclient::LiteServerConfig>> read_liteservers(const std::string &path) {
  TRY_RESULT(data, td::read_file(path));
  TRY_RESULT(json, td::json_decode(data.as_slice()));
  if (json.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("liteserver configuration must be an object");
  }
  tos_api::liteclient_config_global config;
  TRY_STATUS(tos_api::from_json(config, json.get_object()));
  TRY_RESULT(servers, liteclient::LiteServerConfig::parse_global_config(config));
  if (servers.empty() || servers.size() > 16) {
    return td::Status::Error("configure between 1 and 16 trusted liteservers");
  }
  return servers;
}

JsonRpcServer::LiteQuerySender lite_sender(td::actor::ActorId<liteclient::ExtClient> client, double timeout) {
  auto active = std::make_shared<std::atomic<unsigned>>(0);
  return [client, timeout, active](td::BufferSlice query, td::Promise<td::BufferSlice> promise) {
    // This bounds retained transport queries even when clients abandon their
    // HTTP requests before the liteserver answers. No retry of write queries.
    if (query.size() > (4u << 20) || active->fetch_add(1) >= 128) {
      if (query.size() <= (4u << 20)) {
        active->fetch_sub(1);
      }
      promise.set_error(td::Status::Error("liteserver transport capacity exceeded"));
      return;
    }
    td::actor::send_closure(client, &liteclient::ExtClient::send_query, "json-rpc", std::move(query),
                            td::Timestamp::in(timeout),
                            [active, promise = std::move(promise)](td::Result<td::BufferSlice> r) mutable {
                              active->fetch_sub(1);
                              promise.set_result(std::move(r));
                            });
  };
}

namespace {
class ClientCallback final : public http::HttpClient::Callback {
 public:
  void on_ready() override {
  }
  void on_stop_ready() override {
  }
};

class IndexRequest final : public td::actor::Actor {
 public:
  IndexRequest(td::IPAddress address, double timeout, std::string body, std::string source,
               td::Promise<std::string> promise, std::shared_ptr<std::atomic<unsigned>> active)
      : address_(address)
      , timeout_(timeout)
      , body_(std::move(body))
      , source_(std::move(source))
      , promise_(std::move(promise))
      , active_(active) {
  }
  ~IndexRequest() override {
    active_->fetch_sub(1);
  }
  void start_up() override {
    alarm_timestamp() = td::Timestamp::in(timeout_);
    client_ = http::HttpClient::create_multi("", address_, 1, 1, std::make_shared<ClientCallback>());
    auto request = http::HttpRequest::create("POST", "/jsonRPC", "HTTP/1.1").move_as_ok();
    request->add_header({"Host", address_.get_ip_str().str()}).ensure();
    request->add_header({"Content-Type", "application/json"}).ensure();
    request->add_header({"X-Real-IP", source_}).ensure();
    request->add_header({"Content-Length", std::to_string(body_.size())}).ensure();
    request->complete_parse_header().ensure();
    auto payload = request->create_empty_payload().move_as_ok();
    payload->add_chunk(td::BufferSlice(body_));
    payload->complete_parse();
    body_.clear();
    td::actor::send_closure(client_, &http::HttpClient::send_request, std::move(request), std::move(payload),
                            alarm_timestamp(), [self = actor_id(this)](td::Result<JsonRpcServer::HttpReturn> r) {
                              td::actor::send_closure(self, &IndexRequest::received, std::move(r));
                            });
  }
  void received(td::Result<JsonRpcServer::HttpReturn> r) {
    if (r.is_error()) {
      fail(r.move_as_error());
      return;
    }
    auto response = r.move_as_ok();
    if (response.first->code() == 429) {
      fail(td::Status::Error(429, "index service capacity exceeded"));
      return;
    }
    if (response.first->code() != 200) {
      fail(td::Status::Error("index service returned an HTTP error"));
      return;
    }
    payload_ = std::move(response.second);
    class Wake final : public http::HttpPayload::Callback {
     public:
      explicit Wake(td::actor::ActorId<IndexRequest> self) : self_(self) {
      }
      void run(size_t) override {
        td::actor::send_closure(self_, &IndexRequest::drain);
      }
      void completed() override {
        td::actor::send_closure(self_, &IndexRequest::drain);
      }

     private:
      td::actor::ActorId<IndexRequest> self_;
    };
    payload_->add_callback(std::make_unique<Wake>(actor_id(this)));
    drain();
  }
  void drain() {
    if (!payload_)
      return;
    if (payload_->is_error()) {
      fail(td::Status::Error("index response interrupted"));
      return;
    }
    while (payload_->ready_bytes()) {
      auto part = payload_->get_slice(65536);
      if (result_.size() + part.size() > (16u << 20)) {
        fail(td::Status::Error("index response exceeds 16 MiB"));
        return;
      }
      result_.append(part.as_slice().data(), part.size());
    }
    if (payload_->parse_completed()) {
      auto copy = td::BufferSlice(result_);
      auto json = td::json_decode(copy.as_slice());
      if (json.is_error() || json.ok().type() != td::JsonValue::Type::Object) {
        fail(td::Status::Error("invalid index response"));
        return;
      }
      promise_.set_value(std::move(result_));
      stop();
    }
  }
  void alarm() override {
    fail(td::Status::Error("index request timed out"));
  }

 private:
  void fail(td::Status status) {
    if (payload_)
      payload_->fail();
    promise_.set_error(std::move(status));
    stop();
  }
  td::IPAddress address_;
  double timeout_;
  std::string body_, source_, result_;
  td::Promise<std::string> promise_;
  std::shared_ptr<std::atomic<unsigned>> active_;
  td::actor::ActorOwn<http::HttpClient> client_;
  std::shared_ptr<http::HttpPayload> payload_;
};
}  // namespace

JsonRpcServer::IndexQuerySender index_sender(td::IPAddress address, double timeout) {
  auto active = std::make_shared<std::atomic<unsigned>>(0);
  return [address, timeout, active](std::string body, std::string source, td::Promise<std::string> promise) {
    if (body.size() > (4u << 20) || active->fetch_add(1) >= 16) {
      if (body.size() <= (4u << 20))
        active->fetch_sub(1);
      promise.set_error(td::Status::Error("index transport capacity exceeded"));
      return;
    }
    td::actor::create_actor<IndexRequest>("index-request", address, timeout, std::move(body), std::move(source),
                                          std::move(promise), active)
        .release();
  };
}
}  // namespace tos::services
