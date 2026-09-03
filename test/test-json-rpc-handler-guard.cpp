/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// JSON-RPC work runs inside actor callbacks, where an escaping exception
// terminates the validator. `guard_handler` is the single boundary that stops
// that, used both around the dispatcher and around the continuations handlers
// register on other actors. These tests drive that real function with work
// that throws, rather than asserting anything about the code it happens to
// wrap today: what must hold is that nothing escapes, whatever is thrown, and
// that the caller is still answered because unwinding destroys the promise the
// throwing work took ownership of.

#include "validator-engine/json-rpc-handler-guard.h"

#include "td/actor/PromiseFuture.h"
#include "td/utils/tests.h"
#include "vm/excno.hpp"
#include "vm/vm.h"

#include <stdexcept>
#include <string>

namespace tos::validator_engine {
namespace {

TEST(JsonRpcHandlerGuard, RunsWorkThatDoesNotThrow) {
  int calls = 0;
  guard_handler("plain work", [&] { ++calls; });
  ASSERT_EQ(1, calls);
}

TEST(JsonRpcHandlerGuard, ContainsAVmError) {
  // The exception this guard exists for: TVM code reached from a request.
  bool reached_after = false;
  guard_handler("vm error", [] { throw vm::VmError{vm::Excno::cell_und}; });
  reached_after = true;
  ASSERT_TRUE(reached_after);
}

TEST(JsonRpcHandlerGuard, ContainsAVmVirtualizationError) {
  bool reached_after = false;
  guard_handler("vm virt error", [] { throw vm::VmVirtError{}; });
  reached_after = true;
  ASSERT_TRUE(reached_after);
}

TEST(JsonRpcHandlerGuard, ContainsAStandardException) {
  bool reached_after = false;
  guard_handler("std exception", [] { throw std::runtime_error{"boom"}; });
  reached_after = true;
  ASSERT_TRUE(reached_after);
}

TEST(JsonRpcHandlerGuard, ContainsAnExceptionOfAnyOtherType) {
  // Nothing constrains what a future handler, or a library it calls, throws.
  bool reached_after = false;
  guard_handler("foreign exception", [] { throw std::string{"not a std::exception"}; });
  reached_after = true;
  ASSERT_TRUE(reached_after);
}

TEST(JsonRpcHandlerGuard, ThrowingWorkStillAnswersTheCaller) {
  // The property that makes swallowing the exception safe: a handler that
  // throws has taken the request's promise, and unwinding through the guard
  // destroys it, so the client sees an error instead of hanging forever.
  int answers = 0;
  bool got_error = false;
  auto promise = td::PromiseCreator::lambda([&](td::Result<int> r) {
    ++answers;
    got_error = r.is_error();
  });

  guard_handler("throwing handler", [promise = std::move(promise)]() mutable {
    // Ownership moves into the work, exactly as a real handler does before it
    // reaches the code that throws.
    auto owned = std::move(promise);
    throw vm::VmError{vm::Excno::cell_ov};
  });

  ASSERT_EQ(1, answers);
  ASSERT_TRUE(got_error);
}

TEST(JsonRpcHandlerGuard, WorkThatAnsweredBeforeThrowingIsNotAnsweredTwice) {
  // A handler can answer and then throw on the way out. The guard must not
  // turn that into a second, contradictory answer.
  int answers = 0;
  bool first_answer_was_ok = false;
  auto promise = td::PromiseCreator::lambda([&](td::Result<int> r) {
    ++answers;
    if (answers == 1) {
      first_answer_was_ok = r.is_ok();
    }
  });

  guard_handler("handler that answers then throws", [promise = std::move(promise)]() mutable {
    promise.set_value(7);
    throw std::runtime_error{"after answering"};
  });

  ASSERT_EQ(1, answers);
  ASSERT_TRUE(first_answer_was_ok);
}

}  // namespace
}  // namespace tos::validator_engine
