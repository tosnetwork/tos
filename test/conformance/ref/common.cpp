// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Shared helpers and the C entry points of the conformance reference library.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common/refint.h"
#include "td/utils/base64.h"
#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/cellslice.h"
#include "vm/continuation.h"
#include "vm/vm.h"

#include "common.h"
#include "emulator-extern.h"
#include "git.h"

namespace conformance {
namespace {

constexpr std::size_t kMaxContextBytes = 16u << 20;
constexpr int kMaxItemDepth = 32;
constexpr std::size_t kMaxItems = 255;

std::vector<std::pair<std::string, HarnessFn>> &registry() {
  static std::vector<std::pair<std::string, HarnessFn>> harnesses;
  return harnesses;
}

HarnessFn find_harness(td::Slice name) {
  for (const auto &entry : registry()) {
    if (entry.first == name) {
      return entry.second;
    }
  }
  return nullptr;
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

std::string slice_text(const vm::CellSlice &cs) {
  std::ostringstream os;
  os << hash_hex(cs.get_base_cell()) << ':' << cs.cur_pos() << '-' << cs.cur_pos() + cs.size() << ':' << cs.cur_ref()
     << '-' << cs.cur_ref() + cs.size_refs();
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

// Result values nest without a bound in the VM itself, so their text is refused past this depth instead of
// recursing without limit; the tosctl adapter refuses at the same depth (each tuple or continuation adds one).
constexpr int kMaxTextDepth = 512;
// Values are shared, so a shallow result can still expand without limit (a tuple of the same tuple, nested
// thirty times, is 2^30 values of text). One rendering (a final stack, or one value of it) visits at most this
// many values, each counted every time it is visited; the tosctl adapter refuses at the same count.
constexpr std::size_t kMaxTextValues = std::size_t{1} << 20;

struct TextBudget {
  std::size_t values_left = kMaxTextValues;
};

std::string entry_text(const vm::StackEntry &e, int depth, TextBudget &budget);

std::string stack_items_text(const vm::Stack &stack, int depth, TextBudget &budget) {
  std::string out;
  for (int i = static_cast<int>(stack.depth()) - 1; i >= 0; --i) {
    out += (out.empty() ? "" : " ") + entry_text(stack[i], depth, budget);
  }
  return out;
}

// Not compared: the code a continuation carries and its codepage.
std::string continuation_text(const td::Ref<vm::Continuation> &cont, int depth, TextBudget &budget) {
  std::ostringstream os;
  os << "cont:" << cont->type();
  if (auto data = cont->get_cdata()) {
    os << ":nargs=" << data->nargs << ":save=" << savelist(data->save) << ":stack=["
       << (data->stack.is_null() ? "" : stack_items_text(*data->stack, depth, budget)) << ']';
  }
  return os.str();
}

}  // namespace

HarnessRegistrar::HarnessRegistrar(const char *name, HarnessFn fn) {
  registry().emplace_back(name, fn);
}

void init_once() {
  static std::once_flag flag;
  std::call_once(flag, [] {
    SET_VERBOSITY_LEVEL(0);
    emulator_set_verbosity_level(0);
    vm::init_vm().ensure();
  });
}

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

std::string json_bool(bool value) {
  return value ? "true" : "false";
}

std::string hash_hex(const td::Ref<vm::Cell> &cell) {
  return cell->get_hash().to_hex();
}

td::Result<td::Ref<vm::Cell>> boc_from_base64(td::Slice b64) {
  TRY_RESULT(bytes, td::base64_decode(b64));
  TRY_RESULT(cell, vm::std_boc_deserialize(td::Slice(bytes), false, true));
  return cell;
}

td::Result<std::string> boc_to_base64(const td::Ref<vm::Cell> &cell) {
  TRY_RESULT(bytes, vm::std_boc_serialize(cell, 31));
  return td::base64_encode(bytes.as_slice());
}

td::Result<td::Ref<vm::Cell>> required_boc(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(b64, obj.get_required_string_field(field));
  auto cell = boc_from_base64(b64);
  if (cell.is_error()) {
    return td::Status::Error(PSLICE() << field << ": " << cell.error().message());
  }
  return cell.move_as_ok();
}

td::Result<td::Ref<vm::Cell>> optional_boc(td::JsonObject &obj, td::Slice field) {
  if (!obj.has_field(field)) {
    return td::Ref<vm::Cell>{};
  }
  return required_boc(obj, field);
}

td::Result<vm::StackEntry> parse_stack_item(td::JsonValue &value, int depth) {
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
    TRY_RESULT(cell, required_boc(obj, "boc"));
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
      TRY_RESULT(parsed, parse_stack_item(item, depth + 1));
      tuple.push_back(std::move(parsed));
    }
    return vm::StackEntry{td::make_cnt_ref<std::vector<vm::StackEntry>>(std::move(tuple))};
  }
  return td::Status::Error("unknown stack item type");
}

namespace {
std::string entry_text(const vm::StackEntry &e, int depth, TextBudget &budget) {
  if (depth > kMaxTextDepth) {
    throw std::runtime_error("final stack value nested too deep");
  }
  if (budget.values_left == 0) {
    throw std::runtime_error("final stack value too large");
  }
  --budget.values_left;
  switch (e.type()) {
    case vm::StackEntry::t_null:
      return "null";
    case vm::StackEntry::t_int: {
      auto x = e.as_int();
      return x->is_valid() ? x->to_dec_string() : "NaN";
    }
    case vm::StackEntry::t_cell: {
      auto cell = e.as_cell();
      return cell.is_null() ? "cell:nullptr" : "cell:" + hash_hex(cell);
    }
    case vm::StackEntry::t_slice:
      return "slice:" + slice_text(*e.as_slice());
    case vm::StackEntry::t_builder: {
      auto b = e.as_builder();
      std::ostringstream os;
      os << "builder:" << b->size() << ':' << b->size_refs() << ':' << hash_hex(b->finalize_copy());
      return os.str();
    }
    case vm::StackEntry::t_vmcont:
      return continuation_text(e.as_cont(), depth + 1, budget);
    case vm::StackEntry::t_tuple: {
      std::string out = "(";
      for (const auto &item : *e.as_tuple()) {
        out += (out.size() > 1 ? " " : "") + entry_text(item, depth + 1, budget);
      }
      return out + ")";
    }
    default:
      return "other:" + std::to_string(static_cast<int>(e.type()));
  }
}
}  // namespace

std::string stack_entry_text(const vm::StackEntry &entry) {
  TextBudget budget;
  return entry_text(entry, 0, budget);
}

std::string stack_json(const vm::Stack &stack) {
  TextBudget budget;
  std::string out = "[";
  const int depth = static_cast<int>(stack.depth());
  for (int i = depth - 1; i >= 0; --i) {
    out += (i == depth - 1 ? "" : ",") + json_quote(entry_text(stack[i], 0, budget));
  }
  return out + "]";
}

const char *dispatch(const char *context_json, HarnessFn fn) {
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
    auto result = fn(value.get_object());
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

}  // namespace conformance

extern "C" {

const char *conformance_run_v1(const char *harness, const char *context_json) {
  auto fn = harness == nullptr ? nullptr : conformance::find_harness(td::Slice(harness, std::strlen(harness)));
  if (fn == nullptr) {
    return conformance::own(conformance::harness_error("unknown harness"));
  }
  return conformance::dispatch(context_json, fn);
}

int conformance_has_harness(const char *harness) {
  return harness != nullptr && conformance::find_harness(td::Slice(harness, std::strlen(harness))) != nullptr ? 1 : 0;
}

const char *conformance_reference_info(void) {
  const std::string commit = GitMetadata::Populated() ? GitMetadata::CommitSHA1() : std::string();
  std::vector<std::string> names;
  for (const auto &entry : conformance::registry()) {
    names.push_back(entry.first);
  }
  std::sort(names.begin(), names.end());
  std::string list = "[";
  for (std::size_t i = 0; i < names.size(); ++i) {
    list += (i ? "," : "") + conformance::json_quote(names[i]);
  }
  list += "]";
  return conformance::own("{\"reference_commit\":" + conformance::json_quote(commit) +
                          ",\"dirty\":" + conformance::json_bool(GitMetadata::AnyUncommittedChanges()) +
                          ",\"harnesses\":" + list + "}");
}

void conformance_free(const char *str) {
  std::free(const_cast<char *>(str));
}

}  // extern "C"
