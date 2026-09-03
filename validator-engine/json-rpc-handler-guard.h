/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/
#pragma once

#include "td/utils/logging.h"
#include "vm/excno.hpp"
#include "vm/vm.h"

#include <exception>
#include <utility>

namespace tos::validator_engine {

// Runs one piece of request-handling work and stops any exception from leaving
// it.
//
// JSON-RPC work runs inside actor callbacks, and an exception that escapes one
// terminates the validator. Two kinds of work need this: the synchronous body
// of a handler, and the continuations handlers register on other actors, which
// run later on their own stack and are therefore NOT covered by a guard around
// the dispatcher.
//
// The guard does not answer the caller. Work that throws has already taken
// ownership of the request's promise, and unwinding destroys it, which invokes
// its continuation with an error -- so the caller still gets a response and the
// only job here is to keep the exception away from the actor.
//
// `what` names the work in the log; it must outlive the call.
template <typename F>
void guard_handler(const char *what, F &&f) noexcept {
  try {
    std::forward<F>(f)();
  } catch (vm::VmError &err) {
    LOG(WARNING) << "json-rpc: " << what << " raised VM error: " << err.get_msg();
  } catch (vm::VmVirtError &err) {
    LOG(WARNING) << "json-rpc: " << what << " raised VM virtualization error: " << err.get_msg();
  } catch (std::exception &err) {
    LOG(WARNING) << "json-rpc: " << what << " raised exception: " << err.what();
  } catch (...) {
    LOG(WARNING) << "json-rpc: " << what << " raised an unknown exception";
  }
}

}  // namespace tos::validator_engine
