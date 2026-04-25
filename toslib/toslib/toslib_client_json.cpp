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

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "td/utils/Slice.h"
#include "toslib/ClientJson.h"
#include "toslib/Logging.h"
#include "toslib/toslib_client_json.h"

extern "C" int toslib_client_json_square(int x, const char *str) {
  return x * x;
}

void *toslib_client_json_create() {
  return new toslib::ClientJson();
}

void toslib_client_set_verbosity_level(int verbosity_level) {
  toslib::Logging::set_verbosity_level(verbosity_level);
}

void toslib_client_json_destroy(void *client) {
  delete static_cast<toslib::ClientJson *>(client);
}

void toslib_client_json_send(void *client, const char *request) {
  // Codex SDK-FFI audit (S4.1): null-handle no-op (matches the
  // "send/cancel/destroy null no-op" convention from emulator FFI).
  if (client == nullptr) return;
  static_cast<toslib::ClientJson *>(client)->send(td::Slice(request == nullptr ? "" : request));
}

const char *toslib_client_json_receive(void *client, double timeout) {
  // Codex SDK-FFI audit (S4.1): null-handle returns nullptr (the same
  // shape returned for empty receives below).
  if (client == nullptr) return nullptr;
  auto slice = static_cast<toslib::ClientJson *>(client)->receive(timeout);
  if (slice.empty()) {
    return nullptr;
  } else {
    return slice.c_str();
  }
}

const char *toslib_client_json_execute(void *client, const char *request) {
  // Codex SDK-FFI audit (S4.1): execute is static; only the request
  // string can be null. The ternary below already handles that. No
  // guard needed for `client` (unused by the static call).
  (void)client;
  auto slice = toslib::ClientJson::execute(td::Slice(request == nullptr ? "" : request));
  if (slice.empty()) {
    return nullptr;
  } else {
    return slice.c_str();
  }
}

void toslib_client_json_cancel_requests(void *client) {
  // Codex SDK-FFI audit (S4.1): null-handle no-op.
  if (client == nullptr) return;
  static_cast<toslib::ClientJson *>(client)->cancel_requests();
}
