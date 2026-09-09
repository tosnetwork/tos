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

// Regression test for the JSON-RPC request-body reference cycle: an HttpPayload
// owns its callbacks and never clears them, so a body-waiter callback that held
// a strong reference back to the payload kept the whole payload (buffered body
// included) alive for the life of the cycle — surviving the connection and
// leaking on every disconnected or completed request.
//
// JsonRpcPayloadBodyWaiter holds the payload weakly. These tests exercise that
// real base class against a real HttpPayload and assert, via a weak observer,
// that the payload is destroyed once its sole owner drops it — on normal
// completion and on early disconnect alike (a parse error or body timeout is,
// for ownership purposes, the same as an early disconnect: the owner is dropped
// without completion). Reverting the base to hold a shared_ptr re-forms the
// cycle and these assertions fail.

#include <memory>

#include "http/http.h"
#include "td/utils/tests.h"
#include "validator-engine/json-rpc-payload-waiter.h"

namespace http = tos::http;

namespace {

// Mirrors the production waiters: on completion it receives the live payload and
// hands it off without retaining it (production forwards it to an actor message
// that is later dropped).
class RecordingWaiter : public tos::JsonRpcPayloadBodyWaiter {
 public:
  RecordingWaiter(std::weak_ptr<http::HttpPayload> payload, bool& delivered)
      : tos::JsonRpcPayloadBodyWaiter(std::move(payload)), delivered_(delivered) {
  }

 protected:
  void deliver(std::shared_ptr<http::HttpPayload> payload) override {
    delivered_ = true;
    // Let the strong reference go out of scope, as the real handoff does.
  }

 private:
  bool& delivered_;
};

std::shared_ptr<http::HttpPayload> make_payload() {
  return std::make_shared<http::HttpPayload>(http::HttpPayload::PayloadType::pt_chunked, 1 << 20, 4 << 20);
}

}  // namespace

// Body completes normally: the waiter delivers once, and once the connection's
// strong reference is dropped the payload is destroyed — no retain cycle.
TEST(JsonRpcPayloadWaiter, CompletedBodyDoesNotOutliveOwner) {
  bool delivered = false;
  std::weak_ptr<http::HttpPayload> observer;
  {
    auto payload = make_payload();
    observer = payload;
    payload->add_callback(std::make_unique<RecordingWaiter>(payload, delivered));
    payload->complete_parse();
    ASSERT_TRUE(delivered);
    // The connection releases its only strong reference at end of scope.
  }
  ASSERT_TRUE(observer.expired());
}

// Client disconnects before the body completes: completed() never fires, yet
// dropping the owner still destroys the payload, because the callback holds no
// strong reference back to it.
TEST(JsonRpcPayloadWaiter, AbortedBodyDoesNotLeak) {
  bool delivered = false;
  std::weak_ptr<http::HttpPayload> observer;
  {
    auto payload = make_payload();
    observer = payload;
    payload->add_callback(std::make_unique<RecordingWaiter>(payload, delivered));
    // No complete_parse(): the request body never finished arriving.
  }
  ASSERT_TRUE(!delivered);
  ASSERT_TRUE(observer.expired());
}

int main(int argc, char** argv) {
  td::TestsRunner& runner = td::TestsRunner::get_default();
  if (argc > 1) {
    runner.add_substr_filter(argv[1]);
  }
  runner.run_all();
  return runner.any_test_failed() ? 1 : 0;
}
