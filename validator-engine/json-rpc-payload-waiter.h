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
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <memory>

#include "http/http.h"

namespace tos {

// Base for the HttpPayload callbacks the JSON-RPC server registers while a
// request body is still arriving.
//
// An HttpPayload owns its callbacks (std::unique_ptr in HttpPayload::callbacks_)
// and never clears them once completion has been signalled. A callback must
// therefore NOT hold a std::shared_ptr back to the payload: that would form a
// reference cycle (payload -> callback -> payload) that keeps the payload —
// including its buffered request body — alive for as long as the cycle exists.
// The connection, which is the payload's real owner, would release its
// reference on teardown, but the cycle would survive it, so the body would
// never be freed after the client disconnected.
//
// Holding a std::weak_ptr breaks the cycle. The payload's lifetime is then
// governed entirely by its real owners — the connection while the body is
// arriving, plus a transient strong reference handed to the actor that consumes
// the body — so it is reclaimed uniformly across normal completion, early
// disconnect, parse error, and body timeout. The weak reference is upgraded
// exactly once, when the body is complete, to hand a live payload to the
// concrete handler; if the payload is already gone (connection torn down before
// completion) the upgrade fails and nothing is delivered.
class JsonRpcPayloadBodyWaiter : public http::HttpPayload::Callback {
 public:
  explicit JsonRpcPayloadBodyWaiter(std::weak_ptr<http::HttpPayload> payload) : payload_(std::move(payload)) {
  }

  void run(size_t /*ready_bytes*/) override {
  }

  void completed() final {
    if (fired_) {
      return;
    }
    fired_ = true;
    if (auto payload = payload_.lock()) {
      deliver(std::move(payload));
    }
  }

 protected:
  // Invoked at most once, with a live payload, when the body is complete. The
  // handoff must not store the payload anywhere that re-creates a strong cycle
  // back through this callback.
  virtual void deliver(std::shared_ptr<http::HttpPayload> payload) = 0;

 private:
  std::weak_ptr<http::HttpPayload> payload_;
  bool fired_ = false;
};

}  // namespace tos
