/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// The JSON-RPC dispatch boundary catches anything a handler throws so that a
// single handler bug cannot terminate the validator. That guard is only safe
// because the caller still receives an answer: a handler that throws has
// already taken ownership of the request's promise, and stack unwinding
// destroys it. These tests pin the contract the guard depends on -- destroying
// an unfulfilled promise invokes its continuation with an error, exactly once,
// and a promise that was already answered is not answered again. If that ever
// stopped holding, the guard would silently swallow requests and clients would
// hang instead of seeing an error.

#include "td/actor/PromiseFuture.h"
#include "td/utils/tests.h"

#include <memory>

namespace td {
namespace {

TEST(PromiseLossContract, DestroyingAnUnfulfilledPromiseReportsAnError) {
  int calls = 0;
  Status seen = Status::OK();
  {
    auto promise = PromiseCreator::lambda([&](Result<int> r) {
      ++calls;
      seen = r.is_error() ? r.move_as_error() : Status::OK();
    });
    // The promise leaves scope without ever being set -- the shape of a
    // handler that throws after taking ownership of it.
  }
  ASSERT_EQ(1, calls);
  ASSERT_TRUE(seen.is_error());
}

TEST(PromiseLossContract, AnAnsweredPromiseIsNotAnsweredAgainOnDestruction) {
  int calls = 0;
  bool had_value = false;
  {
    auto promise = PromiseCreator::lambda([&](Result<int> r) {
      ++calls;
      had_value = r.is_ok();
    });
    promise.set_value(7);
  }
  ASSERT_EQ(1, calls);
  ASSERT_TRUE(had_value);
}

TEST(PromiseLossContract, ThrowingAfterTakingOwnershipStillAnswersTheCaller) {
  // The exact sequence at the dispatch boundary: the promise is moved into a
  // handler, the handler throws, the boundary catches. The caller must still
  // have been answered, by the moved-to promise being destroyed while the
  // exception unwinds the handler's frame.
  int calls = 0;
  bool got_error = false;
  {
    auto promise = PromiseCreator::lambda([&](Result<int> r) {
      ++calls;
      got_error = r.is_error();
    });
    try {
      auto handler_promise = std::move(promise);
      throw std::runtime_error("handler failed");
    } catch (const std::exception &) {
      // Boundary guard: swallow, having already logged in production.
    }
  }
  ASSERT_EQ(1, calls);
  ASSERT_TRUE(got_error);
}

}  // namespace
}  // namespace td
