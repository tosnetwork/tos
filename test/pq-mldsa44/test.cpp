/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "mldsa44.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef TOS_PQ_TEST_VM
#include "Ed25519.h"
#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/pqops.h"
#include "vm/vm.h"
#endif

namespace {
void require(bool ok, const std::string& why) {
  if (!ok) throw std::runtime_error(why);
}
struct Vector {
  std::string id;
  char expected;
  std::string message, context, signature, key;
};
int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  throw std::runtime_error("bad hex in test input");
}
std::string unhex(const std::string& hex) {
  require(hex.size() <= 131072 && hex.size() % 2 == 0, "invalid hex length");
  std::string out(hex.size() / 2, '\0');
  for (std::size_t i = 0; i < out.size(); ++i) out[i] = char(nibble(hex[2*i]) * 16 + nibble(hex[2*i+1]));
  return out;
}
std::vector<Vector> read_vectors(const std::string& path) {
  std::ifstream f(path);
  require(bool(f), "cannot open vectors: " + path);
  std::vector<Vector> out;
  std::set<std::string> ids;
  for (std::string line; std::getline(f, line);) {
    require(line.size() < 600000, "oversized vector line");
    std::vector<std::string> fields;
    std::size_t pos = 0;
    while (true) {
      auto end = line.find('\t', pos);
      fields.push_back(line.substr(pos, end == std::string::npos ? end : end - pos));
      if (end == std::string::npos) break;
      pos = end + 1;
    }
    require(fields.size() == 6 && fields[1].size() == 1, "bad TSV row");
    require(ids.insert(fields[0]).second, "duplicate vector ID");
    require(fields[1] == "V" || fields[1] == "I" || fields[1] == "M", "bad expected result");
    out.push_back({fields[0], fields[1][0], unhex(fields[2]), unhex(fields[3]), unhex(fields[4]), unhex(fields[5])});
  }
  require(!f.bad() && out.size() >= 3, "empty, truncated or unreadable test corpus");
  require(ids.count("openssl-empty") && ids.count("openssl-maxima") && ids.count("openssl-auth-commitment"),
          "independent positive controls are mandatory");
  return out;
}
char verify(const Vector& v) {
  using tos::pq::VerifyResult;
  switch (tos::pq::verify_mldsa44(v.message, v.context, v.signature, v.key)) {
    case VerifyResult::valid: return 'V';
    case VerifyResult::invalid: return 'I';
    case VerifyResult::malformed_input: return 'M';
    default: throw std::runtime_error(v.id + ": unexpected backend failure");
  }
}
std::vector<Vector> mutations(const Vector& good) {
  std::vector<Vector> out;
  auto add = [&](std::string id, char expected, auto change) {
    auto v = good; v.id = std::move(id); v.expected = expected; change(v); out.push_back(std::move(v));
  };
  for (std::size_t offset : {std::size_t(0), std::size_t(31), std::size_t(100), std::size_t(2419)}) {
    add("signature-bit-" + std::to_string(offset), 'I', [=](auto& v) { v.signature[offset] ^= 1; });
  }
  add("wrong-key", 'I', [](auto& v) { v.key[0] ^= 1; });
  add("wrong-message", 'I', [](auto& v) { v.message[0] ^= 1; });
  add("wrong-context", 'I', [](auto& v) { v.context[0] ^= 1; });
  add("zero-signature", 'I', [](auto& v) { v.signature.assign(2420, '\0'); });
  add("zero-key", 'I', [](auto& v) { v.key.assign(1312, '\0'); });
  add("empty-key", 'M', [](auto& v) { v.key.clear(); });
  add("short-key", 'M', [](auto& v) { v.key.pop_back(); });
  add("long-key", 'M', [](auto& v) { v.key.push_back('\0'); });
  add("other-parameter-key", 'M', [](auto& v) { v.key.resize(1952); });
  add("empty-signature", 'M', [](auto& v) { v.signature.clear(); });
  add("short-signature", 'M', [](auto& v) { v.signature.pop_back(); });
  add("long-signature", 'M', [](auto& v) { v.signature.push_back('\0'); });
  add("message-over-bound", 'M', [](auto& v) { v.message.assign(8193, 'A'); });
  add("context-over-bound", 'M', [](auto& v) { v.context.assign(256, 'B'); });
  return out;
}

#ifdef TOS_PQ_TEST_VM
using Cell = td::Ref<vm::Cell>;
using Cells = std::array<Cell, 4>;
Cell bytes_cell(const std::string& s) {
  if (s.empty()) return vm::CellBuilder().finalize();
  Cell next;
  std::size_t pos = ((s.size() - 1) / 127) * 127;
  while (true) {
    vm::CellBuilder b;
    b.store_bytes(td::Slice{s.data() + pos, std::min<std::size_t>(127, s.size() - pos)});
    if (next.not_null()) b.store_ref(next);
    next = b.finalize();
    if (pos == 0) return next;
    pos -= 127;
  }
}
Cells cells(const Vector& v) {
  return {bytes_cell(v.message), bytes_cell(v.context), bytes_cell(v.signature), bytes_cell(v.key)};
}
Cell opcode() {
  return vm::CellBuilder().store_long(0xf93100, 24).finalize();
}
struct Execution {
  int exit;
  long long gas;
  long long value;
  bool committed;
  std::string c4, c5;
};
Execution execute(const Cells& input, int version = 16, long long budget = 1000000,
                  bool ignore_classic = false, Cell code = {}, bool method_id = false, int repeats = 1) {
  td::Ref<vm::Stack> stack{true};
  for (int i = 0; i < repeats; ++i) for (const auto& cell : input) stack.write().push_cell(cell);
  if (method_id) stack.write().push_smallint(0);
  if (code.is_null()) code = opcode();
  vm::VmState state{vm::load_cell_slice_ref(code), version, std::move(stack), vm::GasLimits{budget, budget}};
  state.set_chksig_always_succeed(ignore_classic);
  const int result = ~state.run();
  long long value = 99;
  if (result == 0) {
    require(state.get_stack().depth() == 1, "unexpected final stack depth");
    value = state.get_stack().pop_int_finite()->to_long();
    require(value == 0 || value == -1, "non-boolean verification result");
  }
  const auto& committed = state.get_committed_state();
  return {result, state.gas_consumed(), value, state.committed(),
          committed.c4.not_null() ? committed.c4->get_hash().to_hex() : "-",
          committed.c5.not_null() ? committed.c5->get_hash().to_hex() : "-"};
}
void print_execution(std::ostream& out, const std::string& id, const Execution& r) {
  out << id << '\t' << r.exit << '\t' << r.value << '\t' << r.gas << '\t' << r.committed
      << '\t' << r.c4 << '\t' << r.c5 << '\n';
}
void check_execution(const Vector& v, const Execution& r) {
  require(r.exit == (v.expected == 'M' ? 9 : 0), v.id + ": wrong VM exit " + std::to_string(r.exit));
  if (v.expected != 'M') require(r.value == (v.expected == 'V' ? -1 : 0), v.id + ": wrong VM result");
}
void vm_boundaries(const Vector& good, std::ostream& out) {
  const auto canonical = cells(good);
  const auto baseline = execute(canonical);
  check_execution(good, baseline);
  // The base fee is independently asserted, not inferred from the implementation.
  const long long floor = 50000 + good.message.size() + good.context.size() + good.signature.size() + good.key.size();
  require(baseline.gas > floor && baseline.gas < floor + 10000, "base gas schedule changed");
  for (int version : {0, 6, 14, 15}) {
    auto r = execute(canonical, version);
    require(r.exit == 6, "instruction accepted before version 16");
    print_execution(out, "version-" + std::to_string(version), r);
  }
  for (long long budget : {49999LL, baseline.gas - 1}) {
    auto r = execute(canonical, 16, budget);
    require(r.exit == -14, "out-of-gas must not return a verification result");
    print_execution(out, "gas-" + std::to_string(budget), r);
  }
  auto exact = execute(canonical, 16, baseline.gas);
  check_execution(good, exact);
  print_execution(out, "exact-gas", exact);
  auto reject = [&](std::string name, Cell replacement, int index = 3) {
    auto changed = canonical; changed[index] = replacement;
    auto r = execute(changed);
    require(r.exit == 9, name + ": wrong structural rejection " + std::to_string(r.exit));
    print_execution(out, name, r);
  };
  auto empty = vm::CellBuilder().finalize();
  reject("non-byte-aligned", vm::CellBuilder().store_long(1, 1).finalize());
  reject("branching", vm::CellBuilder().store_ref(empty).store_ref(empty).finalize());
  reject("short-nonterminal", vm::CellBuilder().store_long(65, 8).store_ref(canonical[3]).finalize());
  reject("empty-nonterminal", vm::CellBuilder().store_ref(canonical[3]).finalize());
  reject("trailing-empty", vm::CellBuilder().store_bytes(std::string(127, 'x')).store_ref(empty).finalize(), 0);
  auto library = vm::CellBuilder().store_long(2, 8).store_bytes(std::string(32, '\0')).finalize(true);
  reject("exotic-library", library);
  auto invalid = good; invalid.signature[0] ^= 1; invalid.expected = 'I';
  auto checked = execute(cells(invalid), 16, 1000000, true);
  check_execution(invalid, checked);
  print_execution(out, "ignore-classic-is-not-pq-bypass", checked);

  // Public BOC transport must retain exactly the bytes consumed by the VM.
  auto restored = canonical;
  for (auto& cell : restored) {
    auto encoded = vm::std_boc_serialize(cell, 2);
    require(encoded.is_ok(), "BOC serialization failed");
    auto decoded = vm::std_boc_deserialize(encoded.ok().as_slice());
    require(decoded.is_ok(), "BOC deserialization failed");
    cell = decoded.move_as_ok();
  }
  auto transported = execute(restored);
  check_execution(good, transported);
  require(transported.gas == baseline.gas, "BOC roundtrip changed gas");
  print_execution(out, "boc-roundtrip", transported);

  vm::CellBuilder repeated;
  for (int i = 0; i < 11; ++i) {
    repeated.store_long(0xf93100, 24);
    if (i != 10) repeated.store_long(0x30, 8);  // DROP the previous result.
  }
  auto eleven = execute(canonical, 16, 1000000, false, repeated.finalize(), false, 11);
  check_execution(good, eleven);
  require(eleven.gas >= 11 * floor, "verification received a free-call allowance");
  print_execution(out, "eleven-paid-calls", eleven);
}

#include "vm-extra-tests.h"
#endif
}  // namespace

int main(int argc, char** argv) {
  try {
    require(argc >= 3, "usage: test vectors.tsv transcript.txt [--benchmark | --code program.boc]");
    auto vectors = read_vectors(argv[1]);
    auto good = std::find_if(vectors.begin(), vectors.end(), [](const auto& v) { return v.id == "openssl-auth-commitment"; });
    require(good != vectors.end() && !good->message.empty() && !good->context.empty(), "missing positive control");
    const Vector control = *good;
    auto changed = mutations(control);
    vectors.insert(vectors.end(), changed.begin(), changed.end());
    std::ofstream transcript(argv[2]);
    require(bool(transcript), "cannot create transcript");
#ifdef TOS_PQ_TEST_VM
    vm::init_vm().ensure();
    SET_VERBOSITY_LEVEL(0);
    Cell compiled;
    if (argc == 5 && std::string(argv[3]) == "--code") {
      std::ifstream f(argv[4], std::ios::binary);
      require(bool(f), "cannot open compiled program");
      std::string raw((std::istreambuf_iterator<char>(f)), {});
      auto decoded = vm::std_boc_deserialize(td::Slice{raw});
      require(decoded.is_ok(), "invalid program BOC");
      compiled = decoded.move_as_ok();
    }
#endif
    std::size_t positives = 0, negatives = 0;
    for (const auto& v : vectors) {
      const char result = verify(v);
      require(result == v.expected, v.id + ": wrapper result " + result + " != " + v.expected);
      positives += result == 'V'; negatives += result != 'V';
#ifdef TOS_PQ_TEST_VM
      auto r = execute(cells(v), 16, 1000000, false, compiled, compiled.not_null());
      check_execution(v, r);
      print_execution(transcript, v.id, r);
      if (compiled.is_null() && v.expected != 'M') {
        require(r.gas == expected_raw_gas(cells(v)), v.id + ": exact gas mismatch");
      }
#else
      transcript << v.id << '\t' << result << '\n';
#endif
    }
    require(positives >= 3 && negatives >= 18, "positive and negative controls did not execute");
#ifdef TOS_PQ_TEST_VM
    vm_boundaries(control, transcript);
    extended_boundaries(control, compiled, transcript);
#endif
    transcript.flush();
    require(bool(transcript), "could not write transcript");
    std::cout << "PASS " << vectors.size() << " vectors (" << positives << " valid, " << negatives << " rejected)\n";
    if (argc == 4 && std::string(argv[3]) == "--benchmark") {
      for (const auto& v : vectors) {
        if (v.id != "openssl-auth-commitment" && v.id != "openssl-maxima" && v.id != "signature-bit-0") continue;
        const int iterations = 1000;
        const auto start = std::chrono::steady_clock::now();
        for (int i = 0; i < iterations; ++i) require(verify(v) == v.expected, "benchmark verification mismatch");
        const double us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count() / iterations;
        std::cout << "BENCH " << v.id << " wrapper_us=" << std::fixed << std::setprecision(3) << us;
#ifdef TOS_PQ_TEST_VM
        auto input = cells(v);
        auto r = execute(input);
        const auto vm_start = std::chrono::steady_clock::now();
        for (int i = 0; i < iterations; ++i) check_execution(v, execute(input));
        const double vm_us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - vm_start).count() / iterations;
        std::cout << " vm_us=" << vm_us << " gas=" << r.gas;
#endif
        std::cout << '\n';
      }
#ifdef TOS_PQ_TEST_VM
      calibrate_gas(vectors, std::string(argv[2]) + ".calibration.json");
#endif
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "FAIL: " << e.what() << '\n';
    return 1;
  }
}
