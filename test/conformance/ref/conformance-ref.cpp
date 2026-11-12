// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Conformance reference: the vm harness over vm::VmState and the txn harness over the transaction
// emulator's C interface, the same native path the existing transaction fixtures use. Contexts are
// validated against the fixture schema by the runner; this file still refuses every value it cannot
// interpret instead of substituting a default.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "common/refint.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Status.h"
#include "td/utils/base64.h"
#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/cellslice.h"
#include "vm/continuation.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

#include "conformance-ref.h"
#include "emulator-extern.h"
#include "git.h"

namespace {

constexpr std::size_t kMaxContextBytes = 16u << 20;
constexpr int kMaxItemDepth = 32;
constexpr std::size_t kMaxItems = 255;
constexpr std::size_t kMaxLibraries = 4;

std::string json_quote(td::Slice s) {
  std::string out = "\"";
  for (std::size_t i = 0; i < s.size(); ++i) {
    const auto c = static_cast<unsigned char>(s[i]);
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out + "\"";
}

const char *own(const std::string &s) {
  auto *p = static_cast<char *>(std::malloc(s.size() + 1));
  if (p != nullptr) {
    std::memcpy(p, s.c_str(), s.size() + 1);
  }
  return p;
}

std::string harness_error(td::Slice message) {
  return "{\"harness_error\":" + json_quote(message) + "}";
}

void init_once() {
  static std::once_flag flag;
  std::call_once(flag, [] {
    SET_VERBOSITY_LEVEL(0);
    emulator_set_verbosity_level(0);
    vm::init_vm().ensure();
  });
}

td::Result<td::Ref<vm::Cell>> boc_from_base64(td::Slice b64) {
  TRY_RESULT(bytes, td::base64_decode(b64));
  TRY_RESULT(cell, vm::std_boc_deserialize(td::Slice(bytes), false, true));
  return cell;
}

// Canonical item text, identical to test/rescue-fee-gate/vm-endstate.cpp so migrated fixtures can be
// cross-checked against that driver's frozen output.
std::string hash(const td::Ref<vm::Cell> &cell) {
  return cell->get_hash().to_hex();
}

std::string slice_text(const vm::CellSlice &cs) {
  std::ostringstream os;
  os << hash(cs.get_base_cell()) << ':' << cs.cur_pos() << '-' << cs.cur_pos() + cs.size() << ':' << cs.cur_ref() << '-'
     << cs.cur_ref() + cs.size_refs();
  return os.str();
}

std::string savelist(const vm::ControlRegs &save) {
  std::string out;
  for (unsigned i = 0; i < 4; ++i) {
    if (save.c[i].not_null()) {
      out += 'c' + std::to_string(i);
    }
  }
  for (unsigned i = 0; i < 2; ++i) {
    if (save.d[i].not_null()) {
      out += 'c' + std::to_string(i + 4);
    }
  }
  if (save.c7.not_null()) {
    out += "c7";
  }
  return out.empty() ? "none" : out;
}

std::string entry_text(const vm::StackEntry &e);

std::string stack_items(const vm::Stack &stack) {
  std::string out;
  for (int i = static_cast<int>(stack.depth()) - 1; i >= 0; --i) {
    out += (out.empty() ? "" : " ") + entry_text(stack[i]);
  }
  return out;
}

std::string continuation_text(const td::Ref<vm::Continuation> &cont) {
  std::ostringstream os;
  os << "cont:" << cont->type();
  if (auto data = cont->get_cdata()) {
    os << ":nargs=" << data->nargs << ":save=" << savelist(data->save) << ":stack=["
       << (data->stack.is_null() ? "" : stack_items(*data->stack)) << ']';
  }
  return os.str();
}

std::string entry_text(const vm::StackEntry &e) {
  switch (e.type()) {
    case vm::StackEntry::t_null:
      return "null";
    case vm::StackEntry::t_int: {
      auto x = e.as_int();
      return x->is_valid() ? x->to_dec_string() : "NaN";
    }
    case vm::StackEntry::t_cell: {
      auto cell = e.as_cell();
      return cell.is_null() ? "cell:nullptr" : "cell:" + hash(cell);
    }
    case vm::StackEntry::t_slice:
      return "slice:" + slice_text(*e.as_slice());
    case vm::StackEntry::t_builder: {
      auto b = e.as_builder();
      std::ostringstream os;
      os << "builder:" << b->size() << ':' << b->size_refs() << ':' << hash(b->finalize_copy());
      return os.str();
    }
    case vm::StackEntry::t_vmcont:
      return continuation_text(e.as_cont());
    case vm::StackEntry::t_tuple: {
      std::string out = "(";
      for (const auto &item : *e.as_tuple()) {
        out += (out.size() > 1 ? " " : "") + entry_text(item);
      }
      return out + ")";
    }
    default:
      return "other:" + std::to_string(static_cast<int>(e.type()));
  }
}

td::Result<vm::StackEntry> parse_item(td::JsonValue &value, int depth) {
  if (depth > kMaxItemDepth) {
    return td::Status::Error("stack item nesting too deep");
  }
  if (value.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("stack item must be an object");
  }
  auto &obj = value.get_object();
  TRY_RESULT(type, obj.get_required_string_field("type"));
  if (type == "null") {
    return vm::StackEntry{};
  }
  if (type == "nan") {
    auto x = td::make_refint(0);
    x.write().invalidate();
    return vm::StackEntry{std::move(x)};
  }
  if (type == "int") {
    TRY_RESULT(text, obj.get_required_string_field("value"));
    auto x = td::dec_string_to_int256(text);
    if (x.is_null() || !x->is_valid() || !x->signed_fits_bits(257)) {
      return td::Status::Error("invalid integer stack item");
    }
    return vm::StackEntry{std::move(x)};
  }
  if (type == "cell" || type == "slice") {
    TRY_RESULT(b64, obj.get_required_string_field("boc"));
    TRY_RESULT(cell, boc_from_base64(b64));
    if (type == "cell") {
      return vm::StackEntry{std::move(cell)};
    }
    return vm::StackEntry{vm::load_cell_slice_ref(std::move(cell))};
  }
  if (type == "tuple") {
    TRY_RESULT(items_value, obj.extract_required_field("items", td::JsonValue::Type::Array));
    auto &items = items_value.get_array();
    if (items.size() > kMaxItems) {
      return td::Status::Error("tuple too long");
    }
    std::vector<vm::StackEntry> tuple;
    tuple.reserve(items.size());
    for (auto &item : items) {
      TRY_RESULT(parsed, parse_item(item, depth + 1));
      tuple.push_back(std::move(parsed));
    }
    return vm::StackEntry{td::make_cnt_ref<std::vector<vm::StackEntry>>(std::move(tuple))};
  }
  return td::Status::Error("unknown stack item type");
}

td::Result<std::string> run_vm(td::JsonObject &ctx) {
  TRY_RESULT(code_b64, ctx.get_required_string_field("code"));
  TRY_RESULT(code, boc_from_base64(code_b64));
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
  td::Ref<vm::Cell> data;
  if (ctx.has_field("data")) {
    TRY_RESULT(data_b64, ctx.get_required_string_field("data"));
    TRY_RESULT_ASSIGN(data, boc_from_base64(data_b64));
  }
  td::Ref<vm::Tuple> c7;
  if (ctx.has_field("c7")) {
    TRY_RESULT(c7_value, ctx.extract_required_field("c7", td::JsonValue::Type::Object));
    TRY_RESULT(c7_entry, parse_item(c7_value, 0));
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
    TRY_RESULT(parsed, parse_item(item, 0));
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
      TRY_RESULT(root, boc_from_base64(library.get_string()));
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

  std::string out = "{\"exit_code\":" + std::to_string(exit_code);
  out += ",\"gas_used\":" + std::to_string(st.gas_consumed());
  out += ",\"steps\":" + std::to_string(st.get_steps_count());
  out += std::string(",\"committed\":") + (committed ? "true" : "false");
  out += ",\"c4_hash\":" + (committed && state.c4.not_null() ? json_quote(hash(state.c4)) : std::string("null"));
  out += ",\"c5_hash\":" + (committed && state.c5.not_null() ? json_quote(hash(state.c5)) : std::string("null"));
  out += ",\"stack\":[";
  const auto &final_stack = st.get_stack();
  for (int i = static_cast<int>(final_stack.depth()) - 1; i >= 0; --i) {
    out += (i == static_cast<int>(final_stack.depth()) - 1 ? "" : ",") + json_quote(entry_text(final_stack[i]));
  }
  return out + "]}";
}

struct EmulatorDeleter {
  void operator()(void *emulator) const {
    transaction_emulator_destroy(emulator);
  }
};

td::Status check_boc(td::Slice name, td::Slice b64) {
  auto cell = boc_from_base64(b64);
  if (cell.is_error()) {
    return td::Status::Error(PSLICE() << name << ": " << cell.error().message());
  }
  return td::Status::OK();
}

td::Result<std::string> run_txn(td::JsonObject &ctx) {
  TRY_RESULT(config, ctx.get_required_string_field("config"));
  TRY_RESULT(shard_account, ctx.get_required_string_field("shard_account"));
  TRY_RESULT(now, ctx.get_required_long_field("now"));
  TRY_RESULT(lt, ctx.get_required_long_field("lt"));
  TRY_RESULT(rand_seed, ctx.get_required_string_field("rand_seed"));
  const bool has_message = ctx.has_field("message");
  const bool has_tick_tock = ctx.has_field("tick_tock");
  if (has_message == has_tick_tock) {
    return td::Status::Error("exactly one of message and tick_tock is required");
  }
  if (now <= 0 || now > 0xffffffffLL || lt <= 0) {
    return td::Status::Error("now and lt must be positive, now must fit 32 bits");
  }
  if (rand_seed.size() != 64 || rand_seed.find_first_not_of("0123456789abcdef") != std::string::npos) {
    return td::Status::Error("rand_seed must be 64 lowercase hex digits");
  }
  TRY_STATUS(check_boc("config", config));
  TRY_STATUS(check_boc("shard_account", shard_account));
  std::string message;
  bool is_tock = false;
  if (has_message) {
    TRY_RESULT_ASSIGN(message, ctx.get_required_string_field("message"));
    TRY_STATUS(check_boc("message", message));
  } else {
    TRY_RESULT(kind, ctx.get_required_string_field("tick_tock"));
    if (kind != "tick" && kind != "tock") {
      return td::Status::Error("tick_tock must be tick or tock");
    }
    is_tock = kind == "tock";
  }
  std::string libraries;
  if (ctx.has_field("libraries")) {
    TRY_RESULT_ASSIGN(libraries, ctx.get_required_string_field("libraries"));
    TRY_STATUS(check_boc("libraries", libraries));
  }
  std::string prev_blocks;
  if (ctx.has_field("prev_blocks")) {
    TRY_RESULT_ASSIGN(prev_blocks, ctx.get_required_string_field("prev_blocks"));
    TRY_STATUS(check_boc("prev_blocks", prev_blocks));
  }

  // A fresh emulator per context, so no setting of one context leaks into the next.
  std::unique_ptr<void, EmulatorDeleter> emulator{transaction_emulator_create(config.c_str(), 0)};
  if (!emulator) {
    return td::Status::Error("config refused by the transaction emulator");
  }
  if (!transaction_emulator_set_unixtime(emulator.get(), static_cast<std::uint32_t>(now)) ||
      !transaction_emulator_set_lt(emulator.get(), static_cast<std::uint64_t>(lt)) ||
      !transaction_emulator_set_rand_seed(emulator.get(), rand_seed.c_str()) ||
      !transaction_emulator_set_ignore_chksig(emulator.get(), false)) {
    return td::Status::Error("transaction emulator refused a context parameter");
  }
  if (!libraries.empty() && !transaction_emulator_set_libs(emulator.get(), libraries.c_str())) {
    return td::Status::Error("transaction emulator refused the libraries");
  }
  if (!prev_blocks.empty() && !transaction_emulator_set_prev_blocks_info(emulator.get(), prev_blocks.c_str())) {
    return td::Status::Error("transaction emulator refused the previous blocks");
  }

  const char *raw =
      has_message ? transaction_emulator_emulate_transaction(emulator.get(), shard_account.c_str(), message.c_str())
                  : transaction_emulator_emulate_tick_tock_transaction(emulator.get(), shard_account.c_str(), is_tock);
  if (raw == nullptr) {
    return td::Status::Error("transaction emulator returned no response");
  }
  std::string response{raw};
  string_destroy(raw);

  TRY_RESULT(parsed, td::json_decode(td::MutableSlice(response)));
  if (parsed.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("transaction emulator response is not an object");
  }
  auto &obj = parsed.get_object();
  TRY_RESULT(success, obj.get_required_bool_field("success"));
  if (success) {
    TRY_RESULT(transaction_b64, obj.get_required_string_field("transaction"));
    TRY_RESULT(shard_account_b64, obj.get_required_string_field("shard_account"));
    TRY_RESULT(transaction_cell, boc_from_base64(transaction_b64));
    TRY_RESULT(shard_account_cell, boc_from_base64(shard_account_b64));
    if (vm::load_cell_slice(shard_account_cell).size_refs() < 1) {
      return td::Status::Error("ShardAccount without an account reference");
    }
    const auto account_cell = vm::load_cell_slice(shard_account_cell).prefetch_ref(0);
    return "{\"outcome\":\"accepted\",\"transaction_hash\":" + json_quote(hash(transaction_cell)) +
           ",\"account_hash\":" + json_quote(hash(account_cell)) +
           ",\"shard_account_hash\":" + json_quote(hash(shard_account_cell)) + "}";
  }
  TRY_RESULT(not_accepted, obj.get_optional_bool_field("external_not_accepted", false));
  if (not_accepted) {
    TRY_RESULT(exit_code, obj.get_required_int_field("vm_exit_code"));
    return "{\"outcome\":\"rejected\",\"vm_exit_code\":" + std::to_string(exit_code) + "}";
  }
  return std::string("{\"outcome\":\"error\"}");
}

const char *dispatch(const char *context_json, td::Result<std::string> (*harness)(td::JsonObject &)) {
  try {
    if (context_json == nullptr) {
      return own(harness_error("null context"));
    }
    const std::size_t length = std::strlen(context_json);
    if (length > kMaxContextBytes) {
      return own(harness_error("context too large"));
    }
    init_once();
    std::string buffer{context_json, length};
    auto parsed = td::json_decode(td::MutableSlice(buffer));
    if (parsed.is_error()) {
      return own(harness_error(PSLICE() << "context is not JSON: " << parsed.error().message()));
    }
    auto value = parsed.move_as_ok();
    if (value.type() != td::JsonValue::Type::Object) {
      return own(harness_error("context must be a JSON object"));
    }
    auto result = harness(value.get_object());
    if (result.is_error()) {
      return own(harness_error(result.error().message()));
    }
    return own(result.ok());
  } catch (const vm::VmError &e) {
    return own(harness_error(PSLICE() << "vm error while reading the context: " << e.get_msg()));
  } catch (const std::exception &e) {
    return own(harness_error(PSLICE() << "exception: " << e.what()));
  } catch (...) {
    return own(harness_error("unknown exception"));
  }
}

}  // namespace

extern "C" {

const char *conformance_vm_v1(const char *context_json) {
  return dispatch(context_json, run_vm);
}

const char *conformance_txn_v1(const char *context_json) {
  return dispatch(context_json, run_txn);
}

const char *conformance_reference_info(void) {
  const std::string commit = GitMetadata::Populated() ? GitMetadata::CommitSHA1() : std::string();
  return own("{\"reference_commit\":" + json_quote(commit) +
             ",\"dirty\":" + (GitMetadata::AnyUncommittedChanges() ? "true" : "false") + "}");
}

void conformance_free(const char *str) {
  std::free(const_cast<char *>(str));
}

}  // extern "C"
