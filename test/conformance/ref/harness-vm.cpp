// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// vm harness: one program on vm::VmState (schema/harness/vm-v1.schema.json).
#include <string>
#include <utility>
#include <vector>

#include "vm/cellslice.h"
#include "vm/vm.h"

#include "common.h"

namespace {

constexpr std::size_t kMaxItems = 255;
constexpr std::size_t kMaxLibraries = 4;

td::Result<std::string> run_vm(td::JsonObject &ctx) {
  TRY_RESULT(code, conformance::required_boc(ctx, "code"));
  TRY_RESULT(version, ctx.get_required_int_field("global_version"));
  TRY_RESULT(flags, ctx.get_optional_int_field("flags", 0));
  if (version < 0 || version > 255 || flags < 0 || flags > 255) {
    return td::Status::Error("global_version and flags must be within 0..255");
  }
  TRY_RESULT(gas_value, ctx.extract_required_field("gas", td::JsonValue::Type::Object));
  auto &gas = gas_value.get_object();
  TRY_RESULT(gas_limit, gas.get_required_long_field("limit"));
  TRY_RESULT(gas_max, gas.get_required_long_field("max"));
  TRY_RESULT(gas_credit, gas.get_optional_long_field("credit", 0));
  if (gas_limit < 0 || gas_max < 0 || gas_credit < 0) {
    return td::Status::Error("gas values must be non-negative");
  }
  TRY_RESULT(data, conformance::optional_boc(ctx, "data"));
  td::Ref<vm::Tuple> c7;
  if (ctx.has_field("c7")) {
    TRY_RESULT(c7_value, ctx.extract_required_field("c7", td::JsonValue::Type::Object));
    TRY_RESULT(c7_entry, conformance::parse_stack_item(c7_value));
    if (!c7_entry.is_tuple()) {
      return td::Status::Error("c7 must be a tuple");
    }
    c7 = c7_entry.as_tuple();
  }
  TRY_RESULT(stack_value, ctx.extract_required_field("stack", td::JsonValue::Type::Array));
  auto &items = stack_value.get_array();
  if (items.size() > kMaxItems) {
    return td::Status::Error("initial stack too deep");
  }
  td::Ref<vm::Stack> stack{true};
  for (auto &item : items) {
    TRY_RESULT(parsed, conformance::parse_stack_item(item));
    stack.write().push(std::move(parsed));
  }
  std::vector<td::Ref<vm::Cell>> libraries;
  if (ctx.has_field("libraries")) {
    TRY_RESULT(libraries_value, ctx.extract_required_field("libraries", td::JsonValue::Type::Array));
    auto &list = libraries_value.get_array();
    if (list.size() > kMaxLibraries) {
      return td::Status::Error("too many library collections");
    }
    for (auto &library : list) {
      if (library.type() != td::JsonValue::Type::String) {
        return td::Status::Error("library collection must be a base64 BOC");
      }
      TRY_RESULT(root, conformance::boc_from_base64(library.get_string()));
      libraries.push_back(std::move(root));
    }
  }

  vm::VmState st{vm::load_cell_slice_ref(code),
                 version,
                 std::move(stack),
                 vm::GasLimits{gas_limit, gas_max, gas_credit},
                 flags,
                 std::move(data),
                 vm::VmLog{},
                 std::move(libraries),
                 std::move(c7)};
  // run() returns out of gas as 13, so ~13 reports it as -14, as transactions do.
  const int exit_code = ~st.run();
  const bool committed = st.committed();
  const auto &state = st.get_committed_state();
  auto committed_hash = [&](const td::Ref<vm::Cell> &cell) {
    return committed && cell.not_null() ? conformance::json_quote(conformance::hash_hex(cell)) : std::string("null");
  };
  return "{\"exit_code\":" + std::to_string(exit_code) + ",\"gas_used\":" + std::to_string(st.gas_consumed()) +
         ",\"steps\":" + std::to_string(st.get_steps_count()) + ",\"committed\":" + conformance::json_bool(committed) +
         ",\"c4_hash\":" + committed_hash(state.c4) + ",\"c5_hash\":" + committed_hash(state.c5) +
         ",\"stack\":" + conformance::stack_json(st.get_stack()) + "}";
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(vm, run_vm);
