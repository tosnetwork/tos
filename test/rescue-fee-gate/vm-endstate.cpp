// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// EXPERIMENT. End-state differential driver (C++ VM): runs the scenarios of suite-parity and
// prints how each execution ended, including the final stack and the committed state, so that
// the Rust VM's end state can be compared field by field (tosctl/src/vm/examples/vm-endstate.rs).
//
// Output, one tab-separated line per scenario:
//     id  exit  gas  steps  committed  c4  c5  stack
// where exit is the external exit code (out of gas -14), committed is 0 or 1, c4/c5 are the
// committed cells' hashes or "-", and stack lists the final stack bottom to top, items separated
// by spaces ("-" when empty), in the canonical form described in vm_endstate_compare.py.
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/continuation.h"
#include "vm/vm.h"

namespace {
std::string unhex(const std::string& s) {
  if (s.size() % 2) {
    throw std::runtime_error("invalid hex length");
  }
  std::string out;
  auto n = [](char c) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    throw std::runtime_error("invalid hex");
  };
  for (std::size_t i = 0; i < s.size(); i += 2) {
    out.push_back(static_cast<char>(n(s[i]) * 16 + n(s[i + 1])));
  }
  return out;
}

td::Ref<vm::Cell> read_boc(const std::string& field) {
  auto bytes = unhex(field);
  auto c = vm::std_boc_deserialize(td::Slice(bytes), false, true);
  if (c.is_error()) {
    throw std::runtime_error("invalid cell BOC");
  }
  return c.move_as_ok();
}

td::Ref<vm::Cell> read_libraries(const std::string& path, std::size_t& remaining) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    throw std::runtime_error("missing library collection");
  }
  std::string bytes(remaining + 1, '\0');
  file.read(bytes.data(), bytes.size());
  const auto size = file.gcount();
  if (file.bad() || size <= 0 || static_cast<std::size_t>(size) > remaining) {
    throw std::runtime_error("invalid library collection size");
  }
  bytes.resize(size);
  remaining -= size;
  auto root = vm::std_boc_deserialize(td::Slice(bytes), false, true);
  if (root.is_error()) {
    throw std::runtime_error("invalid library collection BOC");
  }
  return root.move_as_ok();
}

void push(td::Ref<vm::Stack>& stack, const std::string& field) {
  if (field == "skip") {
    return;
  }
  if (field.rfind("int:", 0) == 0) {
    stack.write().push_smallint(std::stoll(field.substr(4)));
    return;
  }
  stack.write().push_cell(read_boc(field));
}

std::string hash(const td::Ref<vm::Cell>& cell) {
  return cell->get_hash().to_hex();
}

std::string slice(const vm::CellSlice& cs) {
  std::ostringstream os;
  os << hash(cs.get_base_cell()) << ':' << cs.cur_pos() << '-' << cs.cur_pos() + cs.size() << ':' << cs.cur_ref() << '-'
     << cs.cur_ref() + cs.size_refs();
  return os.str();
}

std::string savelist(const vm::ControlRegs& save) {
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

std::string entry(const vm::StackEntry& e);

std::string stack_items(const vm::Stack& stack);

// Not compared: the code a continuation carries (the C++ VM keeps it private) and its codepage
// (the Rust VM keeps one codepage per VM, not per continuation).
std::string continuation(const td::Ref<vm::Continuation>& cont) {
  std::ostringstream os;
  os << "cont:" << cont->type();
  if (auto data = cont->get_cdata()) {
    os << ":nargs=" << data->nargs << ":save=" << savelist(data->save) << ":stack=["
       << (data->stack.is_null() ? "" : stack_items(*data->stack)) << ']';
  }
  return os.str();
}

std::string entry(const vm::StackEntry& e) {
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
      return "slice:" + slice(*e.as_slice());
    case vm::StackEntry::t_builder: {
      auto b = e.as_builder();
      std::ostringstream os;
      os << "builder:" << b->size() << ':' << b->size_refs() << ':' << hash(b->finalize_copy());
      return os.str();
    }
    case vm::StackEntry::t_vmcont:
      return continuation(e.as_cont());
    case vm::StackEntry::t_tuple: {
      std::string out = "(";
      for (const auto& item : *e.as_tuple()) {
        out += (out.size() > 1 ? " " : "") + entry(item);
      }
      return out + ")";
    }
    default:
      return "other:" + std::to_string(static_cast<int>(e.type()));
  }
}

std::string stack_items(const vm::Stack& stack) {
  std::string out;
  for (int i = static_cast<int>(stack.depth()) - 1; i >= 0; --i) {
    out += (out.empty() ? "" : " ") + entry(stack[i]);
  }
  return out;
}

std::string stack_text(const vm::Stack& stack) {
  return stack.depth() ? stack_items(stack) : "-";
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2 || argc > 6) {
      throw std::runtime_error("usage: vm-endstate scenarios.tsv [libraries.boc ...] (at most 4)");
    }
    vm::init_vm().ensure();
    SET_VERBOSITY_LEVEL(0);
    std::vector<td::Ref<vm::Cell>> libraries;
    std::size_t remaining = 1024 * 1024;
    for (int i = 2; i < argc; ++i) {
      libraries.push_back(read_libraries(argv[i], remaining));
    }
    std::ifstream file(argv[1]);
    if (!file) {
      throw std::runtime_error("missing scenarios");
    }
    unsigned count = 0;
    for (std::string line; std::getline(file, line);) {
      std::vector<std::string> f;
      std::istringstream row(line);
      for (std::string x; std::getline(row, x, '\t');) {
        f.push_back(x);
      }
      if (f.size() != 10) {
        throw std::runtime_error("invalid scenario: a program is required");
      }
      const int version = std::stoi(f[1]);
      const long long budget = std::stoll(f[2]);
      td::Ref<vm::Stack> stack{true};
      for (int i = 5; i < 9; ++i) {
        push(stack, f[i]);
      }
      push(stack, f[4]);
      vm::VmState st{vm::load_cell_slice_ref(read_boc(f[9])), version, std::move(stack), vm::GasLimits{budget, budget}};
      for (const auto& library : libraries) {
        if (!st.register_library_collection(library)) {
          throw std::runtime_error("library collection was refused");
        }
      }
      // run() returns out of gas as 13, so ~13 reports it as -14, as transactions do.
      const int exit = ~st.run();
      const auto& committed = st.get_committed_state();
      std::cout << f[0] << '\t' << exit << '\t' << st.gas_consumed() << '\t' << st.get_steps_count() << '\t'
                << (st.committed() ? 1 : 0) << '\t' << (st.committed() ? hash(committed.c4) : "-") << '\t'
                << (st.committed() ? hash(committed.c5) : "-") << '\t' << stack_text(st.get_stack()) << '\n';
      ++count;
    }
    if (file.bad() || count == 0) {
      throw std::runtime_error("incomplete scenario set");
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
