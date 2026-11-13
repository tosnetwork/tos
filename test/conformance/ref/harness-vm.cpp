// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// vm harness: one program on vm::VmState (schema/harness/vm-v1.schema.json).
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "vm/cellslice.h"
#include "vm/vm.h"

#include "common.h"

#ifdef TOS_VM_STEP_TRACE
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#endif

namespace {

constexpr std::size_t kMaxItems = 255;
constexpr std::size_t kMaxLibraries = 4;

#ifdef TOS_VM_STEP_TRACE
// Diagnosis only: the steps and charged cell loads of one run, requested with the context flag "trace". The
// trace is appended to the effects as "trace"; it is not an effect, fixtures cannot request it and the runner
// never compares it. Cell and value digests are the first 16 hex digits of the full hash.
class TraceRecorder final : public vm::StepTraceSink {
 public:
  static constexpr std::size_t kMaxEvents = 1u << 16;

  void on_step(const vm::VmState &vm) override {
    if (!admit()) {
      return;
    }
    // Rendering the top value must not charge the run (a builder is rendered through a finalized copy).
    vm::VmStateInterface::Guard guard{nullptr};
    const auto &stack = vm.get_stack_const();
    const auto code = vm.get_code();
    std::string top = "-";
    if (stack.depth() > 0) {
      top = td::hex_encode(td::sha256(conformance::stack_entry_text(stack[0]))).substr(0, 16);
    }
    std::string where = "-";
    if (code.not_null()) {
      where = code->get_base_cell()->get_hash().to_hex().substr(0, 16) + ":" + std::to_string(code->cur_pos()) + ":" +
              std::to_string(code->cur_ref());
    }
    append("{\"kind\":\"step\",\"step\":" + std::to_string(vm.get_steps_count()) + ",\"gas\":" +
           std::to_string(vm.gas_consumed()) + ",\"depth\":" + std::to_string(vm.trace_stack_depth()) + ",\"top\":\"" +
           top + "\",\"code\":\"" + where + "\"" + (vm.trace_is_child() ? ",\"child\":true" : "") + "}");
  }

  void on_cell_load(const vm::VmState &vm, const vm::CellHash &hash, bool first) override {
    if (!admit()) {
      return;
    }
    append("{\"kind\":\"load\",\"step\":" + std::to_string(vm.get_steps_count()) +
           ",\"gas\":" + std::to_string(vm.gas_consumed()) + ",\"cell\":\"" + hash.to_hex().substr(0, 16) +
           "\",\"first\":" + conformance::json_bool(first) + (vm.trace_is_child() ? ",\"child\":true" : "") + "}");
  }

  std::string json() const {
    return "{\"events\":[" + events_ + "],\"truncated\":" + conformance::json_bool(truncated_) + "}";
  }

 private:
  bool admit() {
    if (count_ >= kMaxEvents) {
      truncated_ = true;
      return false;
    }
    ++count_;
    return true;
  }
  void append(const std::string &event) {
    events_ += (events_.empty() ? "" : ",") + event;
  }

  std::string events_;
  std::size_t count_ = 0;
  bool truncated_ = false;
};

// Installs a recorder as the thread's sink for one run and restores the previous sink.
class TraceScope {
 public:
  explicit TraceScope(vm::StepTraceSink *sink) : saved_(vm::step_trace_sink()) {
    vm::step_trace_sink() = sink;
  }
  ~TraceScope() {
    vm::step_trace_sink() = saved_;
  }
  TraceScope(const TraceScope &) = delete;
  TraceScope &operator=(const TraceScope &) = delete;

 private:
  vm::StepTraceSink *saved_;
};
#endif

td::Result<std::string> run_vm(td::JsonObject &ctx) {
  TRY_RESULT(code, conformance::required_boc(ctx, "code"));
  TRY_RESULT(version, ctx.get_required_int_field("global_version"));
  TRY_RESULT(flags, ctx.get_optional_int_field("flags", 0));
  TRY_RESULT(want_trace, ctx.get_optional_bool_field("trace", false));
#ifndef TOS_VM_STEP_TRACE
  if (want_trace) {
    return td::Status::Error("trace requires a build with TOS_VM_STEP_TRACE");
  }
#endif
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
  // GasLimits adds limit and credit unchecked; refuse contexts where that would overflow.
  if (gas_limit > std::numeric_limits<long long>::max() - gas_credit) {
    return td::Status::Error("gas limit plus credit exceeds 63 bits");
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

  TRY_RESULT(chksig_always_succeed, ctx.get_optional_bool_field("chksig_always_succeed", false));
  td::int64 max_library_loads = -1;
  if (ctx.has_field("max_library_loads")) {
    TRY_RESULT_ASSIGN(max_library_loads, ctx.get_required_long_field("max_library_loads"));
    if (max_library_loads < 0 || max_library_loads > 0xffffffffLL) {
      return td::Status::Error("max_library_loads must fit 32 bits unsigned");
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
  st.set_chksig_always_succeed(chksig_always_succeed);
  if (max_library_loads >= 0) {
    st.set_max_library_loads(static_cast<td::uint32>(max_library_loads));
  }
#ifdef TOS_VM_STEP_TRACE
  TraceRecorder recorder;
  const TraceScope scope{want_trace ? &recorder : nullptr};
#endif
  // run() returns out of gas as 13, so ~13 reports it as -14, as transactions do.
  const int exit_code = ~st.run();
  const bool committed = st.committed();
  const auto &state = st.get_committed_state();
  auto committed_hash = [&](const td::Ref<vm::Cell> &cell) {
    return committed && cell.not_null() ? conformance::json_quote(conformance::hash_hex(cell)) : std::string("null");
  };
  std::string effects =
      "{\"exit_code\":" + std::to_string(exit_code) + ",\"gas_used\":" + std::to_string(st.gas_consumed()) +
      ",\"steps\":" + std::to_string(st.get_steps_count()) + ",\"committed\":" + conformance::json_bool(committed) +
      ",\"c4_hash\":" + committed_hash(state.c4) + ",\"c5_hash\":" + committed_hash(state.c5) +
      ",\"stack\":" + conformance::stack_json(st.get_stack()) + "}";
#ifdef TOS_VM_STEP_TRACE
  if (want_trace) {
    effects.pop_back();
    effects += ",\"trace\":" + recorder.json() + "}";
  }
#endif
  return effects;
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(vm, run_vm);
