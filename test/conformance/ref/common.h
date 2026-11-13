// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Shared helpers of the conformance reference library: harness registry, JSON output, BOC and stack
// decoding, and the canonical text of stack values. A harness lives in its own harness-<name>.cpp and
// registers itself with CONFORMANCE_REGISTER_HARNESS.
#pragma once

#include <string>

#include "td/utils/JsonBuilder.h"
#include "td/utils/Status.h"
#include "vm/cells.h"
#include "vm/stack.hpp"

#include "conformance-ref.h"

namespace conformance {

using HarnessFn = td::Result<std::string> (*)(td::JsonObject &context);

struct HarnessRegistrar {
  HarnessRegistrar(const char *name, HarnessFn fn);
};

// Parses context_json, runs fn, turns errors and exceptions into {"harness_error": ...}. The result is
// allocated with malloc and released by conformance_free.
const char *dispatch(const char *context_json, HarnessFn fn);

// One-time process setup (log verbosity, VM tables).
void init_once();

std::string json_quote(td::Slice s);
std::string json_bool(bool value);
// Uppercase hex of the cell's representation hash, as the C++ node prints it.
std::string hash_hex(const td::Ref<vm::Cell> &cell);

td::Result<td::Ref<vm::Cell>> boc_from_base64(td::Slice b64);
td::Result<std::string> boc_to_base64(const td::Ref<vm::Cell> &cell);
// A required base64 BOC field; a missing or malformed field is an error.
td::Result<td::Ref<vm::Cell>> required_boc(td::JsonObject &obj, td::Slice field);
// An optional base64 BOC field; null when absent.
td::Result<td::Ref<vm::Cell>> optional_boc(td::JsonObject &obj, td::Slice field);

// Input stack value: {"type": null|nan|int|cell|slice|tuple, ...} (schema/common-v1.schema.json).
td::Result<vm::StackEntry> parse_stack_item(td::JsonValue &value, int depth = 0);
// Canonical text of one value: null, decimal, NaN, cell:<hash>, slice:<hash>:<bits>:<refs>,
// builder:<bits>:<refs>:<hash>, cont:<type>[...], (tuple ...).
std::string stack_entry_text(const vm::StackEntry &entry);
// JSON array of canonical texts, bottom of the stack first.
std::string stack_json(const vm::Stack &stack);

}  // namespace conformance

#define CONFORMANCE_REGISTER_HARNESS(name, fn)                                                  \
  extern "C" CONFORMANCE_EXPORT const char *conformance_##name##_v1(const char *context_json) { \
    return ::conformance::dispatch(context_json, fn);                                           \
  }                                                                                             \
  static const ::conformance::HarnessRegistrar conformance_registrar_##name {                   \
    #name, fn                                                                                   \
  }
