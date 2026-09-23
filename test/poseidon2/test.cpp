/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The Poseidon2 t=8 instruction pair, against vectors produced by executing the
// pinned upstream reference, and against the rules that make a permutation safe
// to put in a consensus ISA: it starts at exactly one version, it refuses
// anything that is not already a field element rather than reducing it, and it
// costs what it says it costs.
//
// The vectors are generated, never hand-written: crypto/poseidon2/manifest-gen
// produces both this table and the one the Rust VM uses, and both VMs rebuild
// the same manifest byte stream and compare its digest, so a constant that
// differs between them cannot pass unnoticed.

#include <array>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "openssl/digest.hpp"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cp0.h"
#include "vm/opctable.h"
#include "vm/poseidon2-kat.h"
#include "vm/poseidon2-params.h"
#include "vm/poseidon2ops.h"
#include "vm/pqops.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

namespace {

int failures = 0;

void require(bool ok, const std::string& why) {
  if (!ok) {
    std::cerr << "FAIL  " << why << '\n';
    ++failures;
  }
}

std::string hex(const unsigned char* bytes, std::size_t len) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < len; ++i) {
    out << std::setw(2) << static_cast<unsigned>(bytes[i]);
  }
  return out.str();
}

using State = unsigned char[8][32];

td::RefInt256 int_of(const unsigned char bytes[32]) {
  td::RefInt256 value{true};
  if (!value.write().import_bytes(bytes, 32, false)) {
    throw std::runtime_error("cannot import a 256-bit test value");
  }
  return value;
}

td::Ref<vm::Cell> opcode_cell(unsigned opcode) {
  return vm::CellBuilder().store_long(opcode, 24).finalize();
}

struct Run {
  int exit;
  long long gas;
  std::vector<std::string> stack;  // top last
};

// Runs one instruction over a prepared stack. Anything already on the stack is
// free, so the gas reported is the instruction's own price plus the fixed
// overhead of running a one-instruction continuation.
Run run(unsigned opcode, const std::vector<td::RefInt256>& inputs, int version = 17, long long budget = 1000000,
        td::Ref<vm::Cell> extra = {}) {
  td::Ref<vm::Stack> stack{true};
  for (const auto& value : inputs) {
    stack.write().push_int(value);
  }
  if (extra.not_null()) {
    stack.write().push_cell(extra);
  }
  vm::VmState state{vm::load_cell_slice_ref(opcode_cell(opcode)), version, std::move(stack),
                    vm::GasLimits{budget, budget}};
  const int exit = ~state.run();
  Run result{exit, state.gas_consumed(), {}};
  if (exit == 0) {
    auto& final_stack = state.get_stack();
    std::vector<std::string> reversed;
    while (final_stack.depth() > 0) {
      unsigned char bytes[32];
      auto value = final_stack.pop_int_finite();
      if (!value->export_bytes(bytes, 32, false)) {
        throw std::runtime_error("a result does not fit in 256 unsigned bits");
      }
      reversed.push_back(hex(bytes, 32));
    }
    result.stack.assign(reversed.rbegin(), reversed.rend());
  }
  return result;
}

std::vector<td::RefInt256> state_inputs(const unsigned char state[8][32]) {
  std::vector<td::RefInt256> inputs;
  for (int i = 0; i < 8; ++i) {
    inputs.push_back(int_of(state[i]));
  }
  return inputs;
}

// ---------------------------------------------------------------------------

void check_manifest() {
  namespace p2 = vm::poseidon2;
  const auto bytes = p2::manifest_bytes();
  const std::size_t expected =
      sizeof(p2::manifest_tag) + 32 + 4 +
      32 * (p2::state_width + p2::state_width * p2::state_width + p2::rounds_total * p2::state_width);
  require(bytes.size() == expected,
          "manifest is " + std::to_string(bytes.size()) + " bytes, expected " + std::to_string(expected));
  unsigned char digest[32];
  digest::hash_str<digest::SHA256>(digest, bytes.data(), bytes.size());
  require(std::memcmp(digest, p2::manifest_sha256, 32) == 0,
          "manifest digest " + hex(digest, 32) + " does not match the pinned " + hex(p2::manifest_sha256, 32));
  // Shape, independently of content: a table of the wrong size would still hash.
  require(p2::rounds_total == p2::rounds_f + p2::rounds_p, "round counts do not add up");
  require(p2::rounds_f == 8 && p2::rounds_p == 57, "round counts are not the frozen 8/57");
  require(p2::state_width == 8 && p2::sbox_alpha == 5, "width or S-box degree is not the frozen one");
}

// Nothing below is believed until these pass: they catch a permutation that is
// the identity, one that ignores its input, and a vector table that is degenerate.
void check_instrument() {
  namespace kat = vm::poseidon2::kat;
  State state;
  std::memcpy(state, kat::perm8[0].input, sizeof(state));
  State once;
  std::memcpy(once, state, sizeof(state));
  vm::poseidon2::permute(once);
  require(std::memcmp(once, state, sizeof(state)) != 0, "the permutation returned its input");

  State twice;
  std::memcpy(twice, state, sizeof(state));
  vm::poseidon2::permute(twice);
  require(std::memcmp(once, twice, sizeof(state)) == 0, "the permutation is not deterministic");

  State nudged;
  std::memcpy(nudged, state, sizeof(state));
  nudged[7][31] ^= 1;
  vm::poseidon2::permute(nudged);
  require(std::memcmp(once, nudged, sizeof(state)) != 0, "the last input lane does not reach the output");

  std::memcpy(nudged, state, sizeof(state));
  nudged[0][31] ^= 1;
  vm::poseidon2::permute(nudged);
  require(std::memcmp(once, nudged, sizeof(state)) != 0, "the first input lane does not reach the output");

  for (const auto& vector : kat::perm8) {
    for (int lane = 0; lane < 8; ++lane) {
      require(std::memcmp(vector.output[lane], vm::poseidon2::modulus_be, 32) < 0,
              std::string(vector.name) + ": a frozen output is not below the modulus");
    }
  }
  require(std::memcmp(kat::perm8[0].output, kat::perm8[1].output, sizeof(State)) != 0,
          "two different vectors carry the same frozen output");
}

void check_vectors() {
  namespace kat = vm::poseidon2::kat;
  for (const auto& vector : kat::perm8) {
    State state;
    std::memcpy(state, vector.input, sizeof(state));
    vm::poseidon2::permute(state);
    require(std::memcmp(state, vector.output, sizeof(state)) == 0,
            std::string(vector.name) + ": permutation does not match the pinned reference");

    const auto executed = run(vm::poseidon2_perm8_opcode, state_inputs(vector.input));
    require(executed.exit == 0, std::string(vector.name) + ": PERM8 exited " + std::to_string(executed.exit));
    if (executed.exit == 0) {
      require(executed.stack.size() == 8, std::string(vector.name) + ": PERM8 left a wrong stack depth");
      for (int lane = 0; lane < 8 && lane < static_cast<int>(executed.stack.size()); ++lane) {
        require(executed.stack[lane] == hex(vector.output[lane], 32),
                std::string(vector.name) + ": PERM8 lane " + std::to_string(lane) + " differs in the VM");
      }
    }
  }

  for (const auto& vector : kat::hash7) {
    State state;
    std::memcpy(state, vector.state, sizeof(state));
    vm::poseidon2::permute(state);
    require(std::memcmp(state[0], vector.output, 32) == 0,
            std::string(vector.name) + ": HASH7 reference value differs");

    const auto executed = run(vm::poseidon2_hash7_opcode, state_inputs(vector.state));
    require(executed.exit == 0, std::string(vector.name) + ": HASH7 exited " + std::to_string(executed.exit));
    if (executed.exit == 0) {
      require(executed.stack.size() == 1, std::string(vector.name) + ": HASH7 must leave exactly one value");
      if (!executed.stack.empty()) {
        require(executed.stack[0] == hex(vector.output, 32),
                std::string(vector.name) + ": HASH7 result differs in the VM");
      }
    }
  }

  // HASH7 is lane 0 of the same permutation, and must not be any other lane.
  State state;
  std::memcpy(state, kat::perm8[0].input, sizeof(state));
  const auto permuted = run(vm::poseidon2_perm8_opcode, state_inputs(state));
  const auto hashed = run(vm::poseidon2_hash7_opcode, state_inputs(state));
  require(permuted.exit == 0 && hashed.exit == 0, "the two instructions disagree on a valid state");
  if (permuted.exit == 0 && hashed.exit == 0) {
    require(hashed.stack.at(0) == permuted.stack.at(0), "HASH7 is not lane 0 of PERM8");
    for (int lane = 1; lane < 8; ++lane) {
      require(hashed.stack.at(0) != permuted.stack.at(lane),
              "HASH7 result coincides with lane " + std::to_string(lane));
    }
  }

  // The domain table has its own manifest, rebuilt here the way the generator
  // wrote it. Nothing on chain commits to this digest; it exists so the table
  // cannot drift between the three places it is written.
  {
    std::string stream;
    const char tag[] = "TOS-SHIELDED-DOMAINS-v1";
    stream.append(tag, sizeof(tag));  // the trailing NUL is part of the stream
    stream.push_back(static_cast<char>(std::size(kat::domains)));
    for (const auto& domain : kat::domains) {
      const std::size_t length = std::char_traits<char>::length(domain.label);
      stream.push_back(static_cast<char>(length));
      stream.append(domain.label, length);
      stream.append(reinterpret_cast<const char*>(domain.value), 32);
    }
    unsigned char digest[32];
    digest::hash_str<digest::SHA256>(digest, stream.data(), stream.size());
    require(std::memcmp(digest, kat::domain_manifest_sha256, 32) == 0, "domain manifest digest " + hex(digest, 32) +
                                                                           " does not match the generated " +
                                                                           hex(kat::domain_manifest_sha256, 32));
  }

  for (const auto& domain : kat::domains) {
    bool nonzero = false;
    for (unsigned char byte : domain.value) {
      nonzero = nonzero || byte != 0;
    }
    require(nonzero, std::string(domain.label) + ": domain constant is zero");
    require(std::memcmp(domain.value, vm::poseidon2::modulus_be, 32) < 0,
            std::string(domain.label) + ": domain constant is not below the modulus");
  }
}

void check_version_gate() {
  namespace kat = vm::poseidon2::kat;
  const auto inputs = state_inputs(kat::perm8[0].input);
  for (int version = 0; version <= 16; ++version) {
    for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
      const auto result = run(opcode, inputs, version);
      require(result.exit == 6, "opcode " + hex(reinterpret_cast<const unsigned char*>(&opcode), 3) +
                                    " was accepted at version " + std::to_string(version));
    }
  }
  for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
    require(run(opcode, inputs, 17).exit == 0, "an opcode was refused at version 17");
  }
  // The earlier instruction must not have been dragged forward with it. At 16 it
  // is reachable, so it fails on its own arguments rather than on the version.
  const auto mldsa = run(vm::pq_mldsa44_opcode, {}, 16);
  require(mldsa.exit == 2, "ML-DSA no longer runs at version 16 (exit " + std::to_string(mldsa.exit) + ")");
}

void check_fail_closed() {
  namespace kat = vm::poseidon2::kat;
  namespace p2 = vm::poseidon2;

  auto with_lane = [&](int lane, td::RefInt256 value) {
    auto inputs = state_inputs(kat::perm8[0].input);
    inputs[lane] = std::move(value);
    return inputs;
  };

  unsigned char modulus_minus_one[32];
  std::memcpy(modulus_minus_one, p2::modulus_be, 32);
  modulus_minus_one[31] -= 1;  // the modulus ends in 0x01, so this cannot borrow
  unsigned char all_ones[32];
  std::memset(all_ones, 0xff, 32);

  for (int lane = 0; lane < 8; ++lane) {
    for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
      require(run(opcode, with_lane(lane, int_of(p2::modulus_be))).exit == 5,
              "the modulus itself was accepted in lane " + std::to_string(lane));
      require(run(opcode, with_lane(lane, int_of(all_ones))).exit == 5,
              "2^256-1 was accepted in lane " + std::to_string(lane));
      require(run(opcode, with_lane(lane, -int_of(all_ones))).exit == 5,
              "a negative input was accepted in lane " + std::to_string(lane));
      require(run(opcode, with_lane(lane, td::make_refint(-1))).exit == 5,
              "minus one was accepted in lane " + std::to_string(lane));
      // The boundary below it must still be a legal field element.
      require(run(opcode, with_lane(lane, int_of(modulus_minus_one))).exit == 0,
              "the largest field element was refused in lane " + std::to_string(lane));
    }
  }

  // Nothing is reduced: r and 0 are different inputs and must not agree.
  const auto zero_lane = run(vm::poseidon2_perm8_opcode, with_lane(3, td::make_refint(0)));
  require(zero_lane.exit == 0, "a zero lane was refused");

  for (int depth = 0; depth < 8; ++depth) {
    auto inputs = state_inputs(kat::perm8[0].input);
    inputs.resize(depth);
    for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
      require(run(opcode, inputs).exit == 2, "a stack of " + std::to_string(depth) + " was not an underflow");
    }
  }

  // A non-integer operand is a type error, not a silent conversion.
  auto short_inputs = state_inputs(kat::perm8[0].input);
  short_inputs.pop_back();
  for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
    require(run(opcode, short_inputs, 17, 1000000, vm::CellBuilder().finalize()).exit == 7,
            "a cell operand was not a type error");
  }
}

void check_gas() {
  namespace kat = vm::poseidon2::kat;
  // Specification literals, not implementation constants: the development
  // tariff, the cost of a 24-bit instruction, and the implicit return.
  const long long expected = 2800 + 34 + 5;
  const auto inputs = state_inputs(kat::perm8[0].input);
  for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
    const auto baseline = run(opcode, inputs);
    require(baseline.exit == 0, "gas baseline did not run");
    require(baseline.gas == expected,
            "gas is " + std::to_string(baseline.gas) + ", expected " + std::to_string(expected));
    const auto exact = run(opcode, inputs, 17, baseline.gas);
    require(exact.exit == 0, "the exact budget was not enough");
    const auto starved = run(opcode, inputs, 17, baseline.gas - 1);
    require(starved.exit == -14, "one gas short did not run out of gas");
    // A refused input is still charged: probing must not be free.
    auto bad = inputs;
    bad[0] = int_of(vm::poseidon2::modulus_be);
    const auto refused = run(opcode, bad);
    require(refused.exit == 5, "the refusal changed");
    require(refused.gas >= 2800, "a refused input was charged less than the tariff");
  }
}

void check_opcode_registration() {
  const auto* table = vm::init_op_cp0();
  require(table != nullptr, "the opcode table did not build");
  for (auto [opcode, name] : {std::pair<unsigned, const char*>{vm::poseidon2_perm8_opcode, "POSEIDON2_PERM8"},
                              {vm::poseidon2_hash7_opcode, "POSEIDON2_HASH7"}}) {
    auto slice = vm::load_cell_slice(opcode_cell(opcode));
    const auto dumped = table->dump_instr(slice);
    require(dumped == name, std::string("opcode is registered as '") + dumped + "', expected " + name);
  }

  // Occupancy, asserted rather than assumed: a second instruction at either
  // code must be refused by the table.
  vm::OpcodeTable fresh{"collision probe", vm::Codepage::test_cp};
  vm::register_poseidon2_ops(fresh);
  for (unsigned opcode : {vm::poseidon2_perm8_opcode, vm::poseidon2_hash7_opcode}) {
    const bool inserted =
        fresh.insert_bool(vm::OpcodeInstr::mksimple(opcode, 24, "COLLIDE", [](vm::VmState*) { return 0; }));
    require(!inserted, "a second instruction was accepted at an occupied opcode");
  }
}

// --- POSEIDON2_PATH7 ---------------------------------------------------------
//
// The path fold had no test here at all, and that is how it shipped wrong.
// `poseidon2::permute` works in place, so the permutation's own output lands
// in lane 0; the instruction wrote the domain there once, before the loop, and
// from the second level onwards folded the previous output in place of the
// domain. Every contract test runs in the Rust VM, which writes the domain at
// every level, so nothing disagreed until a pool was deployed on a node and
// its first withdrawal was refused at the nullifier witness.
//
// `reference_fold` below is a second, deliberately plain reading of section
// 7.2. The pinned constant beside it is what the Rust VM produces for the same
// inputs, so the two implementations cannot drift apart again.

// Section 7.2's fold, written out: a fresh state each level, the domain in
// lane 0, the carry at the path digit and the siblings in ascending order.
std::array<unsigned char, 32> reference_fold(const unsigned char leaf[32], const unsigned char domain[32],
                                             const std::vector<std::array<unsigned char, 6 * 32>>& levels,
                                             unsigned long long index) {
  unsigned char carry[32];
  std::memcpy(carry, leaf, 32);
  for (const auto& level : levels) {
    unsigned char state[8][32];
    std::memcpy(state[0], domain, 32);
    const int digit = static_cast<int>(index % 7);
    index /= 7;
    int taken = 0;
    for (int slot = 0; slot < 7; ++slot) {
      if (slot == digit) {
        std::memcpy(state[1 + slot], carry, 32);
      } else {
        std::memcpy(state[1 + slot], level.data() + taken * 32, 32);
        ++taken;
      }
    }
    vm::poseidon2::permute(state);
    std::memcpy(carry, state[0], 32);
  }
  std::array<unsigned char, 32> out{};
  std::memcpy(out.data(), carry, 32);
  return out;
}

// A sibling that is a field element and distinguishable from every other one.
std::array<unsigned char, 32> sibling(int level, int position) {
  std::array<unsigned char, 32> value{};
  value[29] = static_cast<unsigned char>(level + 1);
  value[30] = static_cast<unsigned char>(position + 1);
  value[31] = 0x5b;
  return value;
}

// The path as the instruction reads it: two cells a level, three field
// elements each, chained, the last one carrying no reference.
td::Ref<vm::Cell> build_path(const std::vector<std::array<unsigned char, 6 * 32>>& levels) {
  td::Ref<vm::Cell> next;
  for (auto it = levels.rbegin(); it != levels.rend(); ++it) {
    vm::CellBuilder second;
    for (int i = 3; i < 6; ++i) {
      second.store_bytes(it->data() + i * 32, 32);
    }
    if (next.not_null()) {
      second.store_ref(next);
    }
    auto second_cell = second.finalize();
    vm::CellBuilder first;
    for (int i = 0; i < 3; ++i) {
      first.store_bytes(it->data() + i * 32, 32);
    }
    first.store_ref(second_cell);
    next = first.finalize();
  }
  return next;
}

void check_path7() {
  constexpr int kDepth = 4;
  // Digits 3, 1, 6, 0 in base seven, so no two levels share a position and the
  // top level's digit is zero.
  constexpr unsigned long long kIndex = 3 + 7 * (1 + 7 * (6 + 7 * 0));

  unsigned char leaf[32] = {};
  leaf[31] = 0x11;
  unsigned char domain[32] = {};
  domain[30] = 0x07;
  domain[31] = 0x2b;

  std::vector<std::array<unsigned char, 6 * 32>> levels;
  for (int level = 0; level < kDepth; ++level) {
    std::array<unsigned char, 6 * 32> packed{};
    for (int position = 0; position < 6; ++position) {
      const auto value = sibling(level, position);
      std::memcpy(packed.data() + position * 32, value.data(), 32);
    }
    levels.push_back(packed);
  }

  const auto expected = reference_fold(leaf, domain, levels, kIndex);
  td::Ref<vm::Stack> stack{true};
  stack.write().push_int(int_of(leaf));
  stack.write().push_int(int_of(domain));
  stack.write().push_cell(build_path(levels));
  stack.write().push_int(td::make_refint(static_cast<long long>(kIndex)));
  stack.write().push_int(td::make_refint(kDepth));
  vm::VmState state{vm::load_cell_slice_ref(opcode_cell(vm::poseidon2_path7_opcode)), 18, std::move(stack),
                    vm::GasLimits{1000000, 1000000}};
  const int exit = ~state.run();
  require(exit == 0, "POSEIDON2_PATH7 did not run: exit " + std::to_string(exit));
  if (exit != 0) {
    return;
  }
  unsigned char produced[32];
  auto top = state.get_stack().pop_int_finite();
  require(top->export_bytes(produced, 32, false), "the path root does not fit 256 unsigned bits");

  require(std::memcmp(produced, expected.data(), 32) == 0,
          "POSEIDON2_PATH7 produced " + hex(produced, 32) + ", section 7.2's fold gives " +
              hex(expected.data(), 32) +
              ". The likeliest cause is the domain: `permute` works in place, so lane 0 has to be "
              "rewritten at every level.");

  // And the value the Rust VM produces for the same inputs, pinned by
  // `tosctl/src/vm/src/tests/test_poseidon2.rs`. Two VMs that disagree here do
  // not agree about the chain's state.
  const std::string kRustVm = "12d4dd5748fd48cd8a53067a28ca130a52134c5877c81426b8328cdacfa0ee35";
  require(hex(produced, 32) == kRustVm,
          "POSEIDON2_PATH7 gives " + hex(produced, 32) + " where the Rust VM gives " + kRustVm +
              " for the same path. The two VMs do not agree about the chain's state.");
}

// What one more level of path costs, which has to be the same number in both
// VMs or the two do not agree about how much a transaction spent.
//
// Measured as a difference rather than an absolute, because the fixed overhead
// of running a one-instruction continuation is this harness's, not the
// instruction's. The Rust VM pins the absolute in
// `tosctl/src/vm/tests/test_poseidon2.rs` as
// `500 + depth * 3000 + 2 * depth * 100`: a level is one permutation at the
// tariff plus the two cells it reads, at the ordinary first-load price.
long long path7_gas(int depth) {
  std::vector<std::array<unsigned char, 6 * 32>> levels;
  for (int level = 0; level < depth; ++level) {
    std::array<unsigned char, 6 * 32> packed{};
    for (int position = 0; position < 6; ++position) {
      const auto value = sibling(level, position);
      std::memcpy(packed.data() + position * 32, value.data(), 32);
    }
    levels.push_back(packed);
  }
  unsigned char leaf[32] = {};
  leaf[31] = 0x11;
  unsigned char domain[32] = {};
  domain[31] = 0x2b;
  td::Ref<vm::Stack> stack{true};
  stack.write().push_int(int_of(leaf));
  stack.write().push_int(int_of(domain));
  stack.write().push_cell(build_path(levels));
  stack.write().push_int(td::make_refint(0));
  stack.write().push_int(td::make_refint(depth));
  vm::VmState state{vm::load_cell_slice_ref(opcode_cell(vm::poseidon2_path7_opcode)), 18, std::move(stack),
                    vm::GasLimits{10000000, 10000000}};
  const int exit = ~state.run();
  require(exit == 0, "POSEIDON2_PATH7 did not run at depth " + std::to_string(depth));
  return state.gas_consumed();
}

// The same run, with the index as a parameter and the refusal kept rather
// than asserted away. A malformed operand has a price as well as an
// exception, and the price is the half nobody was checking.
struct Path7Run {
  int exit;
  long long gas;
};

Path7Run path7_run(int depth, td::RefInt256 index) {
  std::vector<std::array<unsigned char, 6 * 32>> levels;
  for (int level = 0; level < depth; ++level) {
    std::array<unsigned char, 6 * 32> packed{};
    for (int position = 0; position < 6; ++position) {
      const auto value = sibling(level, position);
      std::memcpy(packed.data() + position * 32, value.data(), 32);
    }
    levels.push_back(packed);
  }
  unsigned char leaf[32] = {};
  leaf[31] = 0x11;
  unsigned char domain[32] = {};
  domain[31] = 0x2b;
  td::Ref<vm::Stack> stack{true};
  stack.write().push_int(int_of(leaf));
  stack.write().push_int(int_of(domain));
  stack.write().push_cell(build_path(levels));
  stack.write().push_int(std::move(index));
  stack.write().push_int(td::make_refint(depth));
  vm::VmState state{vm::load_cell_slice_ref(opcode_cell(vm::poseidon2_path7_opcode)), 18, std::move(stack),
                    vm::GasLimits{10000000, 10000000}};
  const int exit = ~state.run();
  return Path7Run{exit, state.gas_consumed()};
}

// An index that does not fit its depth costs the base and nothing else.
//
// This is the assertion that was missing, and its absence let the two VMs
// charge differently for one public instruction. The Rust VM decides the
// index from `(index, depth)` before touching a cell; this one used to run
// every level first and refuse afterwards, so the same operand cost 500 gas
// there and 500 plus twelve levels here.
//
// Both halves matter. Asserting only the exception -- which the Rust
// malformed corpus did -- leaves the price free to diverge, and the price is
// what a node charges.
void check_path7_index_refusal_is_cheap() {
  constexpr int kDepth = 12;
  // 7^12, the smallest index that needs a thirteenth base-seven digit.
  td::RefInt256 past = td::make_refint(1);
  for (int i = 0; i < kDepth; ++i) {
    past = past * td::make_refint(7);
  }

  const Path7Run refused = path7_run(kDepth, past);
  require(refused.exit == static_cast<int>(vm::Excno::range_chk),
          "an index past the depth exited " + std::to_string(refused.exit) +
              ", not a range check");

  // What a refusal at depth 1 costs, which is the base plus this harness's
  // own fixed cost and no level at all. A refusal at depth 12 must cost the
  // same: the index is decided before any level is charged, so depth cannot
  // enter the price of refusing it.
  const Path7Run shallow = path7_run(1, td::make_refint(7));
  require(shallow.exit == static_cast<int>(vm::Excno::range_chk),
          "an index past a depth of one was not refused");
  require(refused.gas == shallow.gas,
          "refusing an oversized index cost " + std::to_string(refused.gas) +
              " gas at depth 12 and " + std::to_string(shallow.gas) +
              " at depth 1. The index must be decided before any level is "
              "charged, or the price of a malformed operand grows with a depth "
              "whose levels are never walked.");

  // And it is cheaper than doing the work, by about the levels it skips.
  const long long honest = path7_gas(kDepth);
  require(refused.gas * 4 < honest,
          "refusing an oversized index cost " + std::to_string(refused.gas) +
              " against " + std::to_string(honest) +
              " for walking the path, which is not the early refusal this "
              "claims to be.");
}

void check_path7_gas() {
  // A level is the tariff plus the two cells it reads. `cell_load_gas_price`
  // is 100, and both cells are new to this transaction.
  constexpr long long kPerLevel = 3000 + 2 * 100;
  const long long four = path7_gas(4);
  const long long five = path7_gas(5);
  // The base, isolated. Extrapolating back to depth zero leaves the base plus
  // this harness's own fixed cost for running a one-instruction continuation,
  // so the constant below is that sum and not the tariff alone. Without this
  // the C++ base price is unguarded: the delta check cancels it exactly, and
  // setting `poseidon2_path7_base_gas_price` to zero passed every C++ test
  // while the Rust VM's absolute pinned it. Two VMs that disagree about what a
  // withdrawal costs do not agree at all.
  //
  // Written as literals, like the Rust VM's absolute and for the same reason:
  // a test that reads the constant it is checking cannot check it. 500 is the
  // base; 39 is what this harness costs to run one instruction, and is the
  // same 39 the Rust test spells `34 + 5`.
  constexpr long long kBaseAndHarness = 500 + 39;
  const long long intercept = four - 4 * kPerLevel;
  require(intercept == kBaseAndHarness,
          "POSEIDON2_PATH7 extrapolates back to " + std::to_string(intercept) +
              " at depth zero, not " + std::to_string(kBaseAndHarness) +
              ". The base price is the only thing in that figure that should ever move, and "
              "it may not move in one VM alone.");
  require(five - four == kPerLevel,
          "one more level of POSEIDON2_PATH7 costs " + std::to_string(five - four) + ", not " +
              std::to_string(kPerLevel) +
              ". The Rust VM charges the tariff plus two cell loads a level, and a chain whose two "
              "VMs price an instruction differently does not agree with itself about how much a "
              "transaction spent.");
}

}  // namespace

int main() {
  const std::pair<const char*, void (*)()> stages[] = {
      {"manifest", check_manifest},
      {"instrument", check_instrument},
      {"vectors", check_vectors},
      {"version gate", check_version_gate},
      {"fail closed", check_fail_closed},
      {"gas", check_gas},
      {"opcode registration", check_opcode_registration},
      {"path7", check_path7},
      {"path7 gas", check_path7_gas},
      {"path7 index refusal is cheap", check_path7_index_refusal_is_cheap},
  };
  // The VM narrates every instruction at info level; only failures matter here.
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  // The dispatch table registers itself only when it is first built.
  vm::init_op_cp0();
  try {
    for (const auto& [name, stage] : stages) {
      std::cout << "-- " << name << std::endl;
      stage();
    }
  } catch (const std::exception& e) {
    std::cerr << "FAIL  unexpected exception: " << e.what() << '\n';
    ++failures;
  }
  if (failures != 0) {
    std::cerr << failures << " check(s) failed\n";
    return 1;
  }
  std::cout << "poseidon2: all checks passed\n";
  return 0;
}
