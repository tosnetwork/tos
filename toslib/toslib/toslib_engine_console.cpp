#include "auto/tl/tos_api_json.h"
#include "tl-utils/tl-utils.hpp"
#include "tl/tl_json.h"

#include "FFIAwaitable.h"
#include "FFIEngineConsoleClient.h"
#include "FFIEventLoop.h"
#include "toslib_engine_console.h"

// ===== Event loop =====
ToslibEventLoop *toslib_event_loop_create(int threads) {
  return new toslib::FFIEventLoop{threads};
}

void toslib_event_loop_destroy(ToslibEventLoop *loop) {
  // Codex SDK-FFI audit (S4.1): null-loop is a no-op (delete on nullptr
  // is well-defined; explicit guard documents intent).
  delete loop;
}

void toslib_event_loop_cancel(ToslibEventLoop *loop) {
  // Codex SDK-FFI audit (S4.1): null-handle no-op.
  if (loop == nullptr) return;
  loop->cancel();
}

const void *toslib_event_loop_wait(ToslibEventLoop *loop, double timeout) {
  // Codex SDK-FFI audit (S4.1): null-handle returns nullptr (same shape
  // as the no-result branch below).
  if (loop == nullptr) return nullptr;
  auto result = loop->wait(timeout);
  if (!result.has_value()) {
    return nullptr;
  }
  return result->ptr();
}

// ===== Response =====
void toslib_response_destroy(ToslibResponse *response) {
  // Codex SDK-FFI audit (S4.1): null-handle no-op.
  if (response == nullptr) return;
  response->destroy();
}

bool toslib_response_await_ready(ToslibResponse *response) {
  // Codex SDK-FFI audit (S4.1): null-handle treated as not-ready (false).
  if (response == nullptr) return false;
  return response->await_ready();
}

void toslib_response_await_suspend(ToslibResponse *response, const void *continuation) {
  // Codex SDK-FFI audit (S4.1): null-handle no-op.
  if (response == nullptr) return;
  response->await_suspend({continuation});
}

bool toslib_response_is_error(ToslibResponse *response) {
  // Codex SDK-FFI audit (S4.1): null-handle reports error (true).
  if (response == nullptr) return true;
  return response->result().is_error();
}

int toslib_response_get_error_code(ToslibResponse *response) {
  // Codex SDK-FFI audit (S4.1): null-handle returns -1.
  if (response == nullptr) return -1;
  return response->result().error().code();
}

const char *toslib_response_get_error_message(ToslibResponse *response) {
  // Codex SDK-FFI audit (S4.1): null-handle returns empty C string.
  if (response == nullptr) return "";
  return response->result().error().message().data();
}

const char *toslib_response_get_response(ToslibResponse *response) {
  // Codex SDK-FFI audit (S4.1): null-handle returns empty C string.
  if (response == nullptr) return "";
  return response->result().ok().data();
}

// ===== Engine Console =====
namespace {

td::Result<toslib::FFIEngineConsoleClient> create_ffi_client(ToslibEventLoop *loop, const char *config) {
  // Codex SDK-FFI audit (S4.1): `std::string config_str = config;` is UB
  // when config==nullptr; loop->* defererences null. Reject up front.
  if (loop == nullptr) {
    return td::Status::Error("create_ffi_client: null event loop");
  }
  if (config == nullptr) {
    return td::Status::Error("create_ffi_client: null config string");
  }
  std::string config_str = config;
  TRY_RESULT(json, td::json_decode(config_str));
  if (json.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("Config must be a JSON object");
  }

  tos::tos_api::engineConsoleClient_config parsed_config;
  TRY_STATUS(from_json(parsed_config, json.get_object()));

  td::IPAddress parsed_address;
  TRY_STATUS(parsed_address.init_host_port(parsed_config.address_));

  if (!parsed_config.server_public_key_) {
    return td::Status::Error("server_public_key is required in config");
  }
  auto server_public_key_slice = tos::serialize_tl_object(parsed_config.server_public_key_.get(), true);
  TRY_RESULT(parsed_server_public_key, tos::PublicKey::import(server_public_key_slice));

  if (!parsed_config.client_private_key_) {
    return td::Status::Error("client_private_key is required in config");
  }
  auto client_private_key_slice = tos::serialize_tl_object(parsed_config.client_private_key_.get(), true);
  TRY_RESULT(parsed_client_private_key, tos::PrivateKey::import(client_private_key_slice));

  return toslib::FFIEngineConsoleClient{*loop, parsed_address, parsed_server_public_key, parsed_client_private_key};
}

td::Result<tos::tl_object_ptr<tos::tos_api::Function>> parse_query(const char *query) {
  // Codex SDK-FFI audit (S4.1): same null-string guard as create_ffi_client.
  if (query == nullptr) {
    return td::Status::Error("parse_query: null query string");
  }
  std::string query_str = query;
  TRY_RESULT(json, td::json_decode(query_str));
  if (json.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("Query must be a JSON object");
  }

  tos::tl_object_ptr<tos::tos_api::Function> parsed_query;
  TRY_STATUS(from_json(parsed_query, std::move(json)));

  if (!toslib::is_engine_console_query(parsed_query)) {
    return td::Status::Error("Query is not an engine console query");
  }

  return parsed_query;
}

}  // namespace

struct ToslibEngineConsole {
  td::Result<toslib::FFIEngineConsoleClient> client;
};

ToslibEngineConsole *toslib_engine_console_create(ToslibEventLoop *loop, const char *config) {
  // Codex SDK-FFI audit (S4.1): create_ffi_client already null-guards
  // both inputs; the returned ToslibEngineConsole carries the failure
  // as `client.is_error()`, so callers see a structured error object
  // rather than a crashing dereference.
  return new ToslibEngineConsole{create_ffi_client(loop, config)};
}

void toslib_engine_console_destroy(ToslibEngineConsole *console) {
  // Codex SDK-FFI audit (S4.1): delete on nullptr is well-defined.
  delete console;
}

bool toslib_engine_console_is_error(ToslibEngineConsole *console) {
  // Codex SDK-FFI audit (S4.1): null-handle reports error (true).
  if (console == nullptr) return true;
  return console->client.is_error();
}

int toslib_engine_console_get_error_code(ToslibEngineConsole *console) {
  // Codex SDK-FFI audit (S4.1): null-handle returns -1.
  if (console == nullptr) return -1;
  return console->client.error().code();
}

const char *toslib_engine_console_get_error_message(ToslibEngineConsole *console) {
  // Codex SDK-FFI audit (S4.1): null-handle returns empty C string.
  if (console == nullptr) return "";
  return console->client.error().message().data();
}

ToslibResponse *toslib_engine_console_request(ToslibEngineConsole *console, const char *query) {
  // Codex SDK-FFI audit (S4.1): null-handle returns nullptr (caller
  // checks via toslib_response_*, which are also null-safe now).
  if (console == nullptr) return nullptr;
  // Caller must check is_error() before calling request(); if the
  // console was constructed in an error state, ok_ref() would abort.
  if (console->client.is_error()) return nullptr;
  auto &client = console->client.ok_ref();

  auto query_or_sync_error = parse_query(query);

  if (query_or_sync_error.is_error()) {
    return ToslibResponse::create_resolved(client.loop(), query_or_sync_error.move_as_error());
  }

  auto transform = [](tos::tl_object_ptr<tos::tos_api::Object> object) -> std::string {
    return td::json_encode<std::string>(td::ToJson(object));
  };

  auto [response, promise] =
      ToslibResponse::create_bridge<tos::tl_object_ptr<tos::tos_api::Object>>(client.loop(), transform);
  client.request(query_or_sync_error.move_as_ok(), std::move(promise));
  return response;
}
