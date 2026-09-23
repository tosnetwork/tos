/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
// B1, the C++ half: what POSEIDON2_PERM8 and POSEIDON2_HASH7 cost here.
//
// A tariff has to cover the slower of the two implementations, so measuring
// one of them settles nothing. This runs the *same compiled probe* the Rust
// benchmark runs -- `tools/poseidon2-bench` writes it out -- because two
// implementations timed on two different programs would be a comparison of
// the programs.
//
// The method is the same as well: each subject is timed against a loop that
// does everything except the instruction, the two are measured back to back
// so that drift lands on both, and the per-repeat difference is minimised
// rather than averaged.

#include <chrono>

#include "vm/poseidon2ops.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "common/bitstring.h"
#include "td/utils/base64.h"
#include "td/utils/buffer.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/cells.h"
#include "vm/cp0.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

namespace {

struct Subject {
  const char* name;
  // The gas price already in crypto/vm/vm.h, or 0 for the two being priced.
  long long price;
  unsigned method_id;
  unsigned baseline_id;
};

// The method ids the Rust benchmark prints when it writes the probe. They are
// crc16-derived and stable; a mismatch would show up as an unknown-method exit
// rather than a wrong number.
//
// CHKSIGNU is absent on purpose. It was the one anchor whose cost is not point
// decompression, but given the same invalid signature the two VMs charge the
// same gas and take 67 ns and 32,441 ns: this one rejects before verifying and
// the other does not. An anchor the two implementations disagree about by four
// hundred times cannot calibrate either of them.
// POSEIDON2_PATH7 appears three times because it is two numbers, not one: a
// base and a per-level cost, which no single depth can separate. Depth 12 is
// what both trees use and is measured rather than interpolated; 1 and 32 are
// far enough either side that the base does not vanish into the noise.
const std::vector<Subject> kSubjects = {
    {"POSEIDON2_PERM8", 0, 118365, 113038},       {"POSEIDON2_HASH7", 0, 80881, 65739},
    {"POSEIDON2_PATH7_D1", 0, 93672, 77996},      {"POSEIDON2_PATH7_D12", 0, 82714, 99733},
    {"POSEIDON2_PATH7_D32", 0, 75128, 124278},    {"BLS_G1_ADD", 3900, 71435, 95410},
    {"BLS_G1_NEG", 750, 79976, 121841},           {"BLS_G1_INGROUP", 2950, 118906, 70687},
    {"BLS_G2_ADD", 6100, 129497, 116093},
};

struct Sample {
  double nanos;
  long long gas;
  int exit;
};

// One execution of one get-method over the probe's code.
Sample run_once(td::Ref<vm::Cell> code, unsigned method_id, int rounds) {
  td::Ref<vm::Stack> stack{true};
  stack.write().push_smallint(rounds);
  stack.write().push_smallint(static_cast<long long>(method_id));
  const long long budget = 1ll << 50;
  // flags = 1 is `same_c3`: c3 is the code, so `CALLDICT` reaches the probe's
  // own functions. Without it `init_cregs` sets c3 to `QuitCont{11}` and every
  // call out of a method exits 11 -- which is exactly what a subject needing a
  // FunC helper did. Every earlier subject was an inline `asm` with no call in
  // it, so this harness had never once executed a CALLDICT and the defect was
  // invisible for as long as nothing needed one.
  //
  // `poseidon2_path7_min_version`, not `poseidon2_min_version`: PATH7 ships a
  // version later than the other two, and at 17 it is not an instruction.
  vm::VmState state{vm::load_cell_slice_ref(code), vm::poseidon2_path7_min_version, std::move(stack),
                    vm::GasLimits{budget, budget}, 1};
  const auto started = std::chrono::steady_clock::now();
  const int exit = ~state.run();
  const auto elapsed = std::chrono::steady_clock::now() - started;
  return Sample{std::chrono::duration<double, std::nano>(elapsed).count(), state.gas_consumed(), exit};
}

// One subject against its own baseline: back to back inside each repeat, and
// the smallest difference wins. A shared machine drifts, and a drift that
// lands on one pass and not the other is subtracted straight into the answer.
struct Measured {
  double nanos_per_op;
  long long gas_per_op;
};

Measured measure(td::Ref<vm::Cell> code, const Subject& subject, int rounds, int repeats) {
  run_once(code, subject.method_id, rounds);
  run_once(code, subject.baseline_id, rounds);
  double best = 1e300;
  long long gas_per_op = 0;
  for (int repeat = 0; repeat < repeats; ++repeat) {
    const Sample with = run_once(code, subject.method_id, rounds);
    const Sample without = run_once(code, subject.baseline_id, rounds);
    if (with.exit != 0 || without.exit != 0) {
      std::fprintf(stderr, "%s exited %d/%d\n", subject.name, with.exit, without.exit);
      std::exit(1);
    }
    const double per_op = (with.nanos - without.nanos) / rounds;
    best = per_op < best ? per_op : best;
    gas_per_op = (with.gas - without.gas) / rounds;
  }
  return Measured{best, gas_per_op};
}

}  // namespace

// The permutation on its own, with no VM around it. The anchored figures
// above run the instruction, so they carry the stack handling and the
// conversions; when the two VMs disagree about this instruction by more than
// they disagree about everything else, this says whether the disagreement is
// in the cryptography or in the plumbing. `poseidon2-bench --direct` on the
// Rust side does the same thing.
int direct_permutation() {
  unsigned char state[8][32];
  for (int lane = 0; lane < 8; ++lane) {
    std::memset(state[lane], 0, 32);
    state[lane][31] = static_cast<unsigned char>(lane + 1);
  }
  vm::poseidon2::permute(state);  // warm anything that is lazily built
  const int rounds = 200000;
  double best = 1e18;
  for (int pass = 0; pass < 3; ++pass) {
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < rounds; ++i) {
      vm::poseidon2::permute(state);
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    double ns =
        double(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count()) / rounds;
    if (ns < best) {
      best = ns;
    }
  }
  // Keep the result live.
  std::fprintf(stderr, "%s", state[0][31] == 0xff ? "" : "");
  std::printf("POSEIDON2_PERM8 direct: %.0f ns per permutation\n", best);
  return 0;
}

int main(int argc, char** argv) {
  if (argc > 1 && std::string(argv[1]) == "--direct") {
    return direct_permutation();
  }
  if (argc < 2) {
    std::fprintf(stderr,
                 "usage: bench-poseidon2 <probe.boc> [rounds] [repeats]\n"
                 "the probe is written by tools/poseidon2-bench with\n"
                 "POSEIDON2_BENCH_DUMP_CODE set.\n");
    return 2;
  }
  const int rounds = argc > 2 ? std::atoi(argv[2]) : 2000;
  const int repeats = argc > 3 ? std::atoi(argv[3]) : 15;

  auto bytes = td::read_file(td::CSlice(argv[1]));
  if (bytes.is_error()) {
    std::fprintf(stderr, "cannot read %s\n", argv[1]);
    return 1;
  }
  auto code = vm::std_boc_deserialize(bytes.move_as_ok());
  if (code.is_error()) {
    std::fprintf(stderr, "%s is not a BOC\n", argv[1]);
    return 1;
  }
  vm::init_op_cp0();
  // A failing probe reports only an exit code, which says what kind of
  // error and nothing about where. This lets a run be turned up.
  SET_VERBOSITY_LEVEL(std::getenv("BENCH_VERBOSE") ? verbosity_DEBUG : verbosity_ERROR);

  std::printf("C++ VM, %d rounds, best of %d\n\n", rounds, repeats);
  std::printf("%-18s%10s%10s%12s%14s\n", "instruction", "ns/op", "gas/op", "known gas", "ns per gas");

  std::vector<std::pair<const Subject*, double>> anchors;
  std::vector<std::pair<const Subject*, double>> unpriced;
  for (const auto& subject : kSubjects) {
    const Measured measured = measure(code.ok(), subject, rounds, repeats);
    if (subject.price > 0) {
      std::printf("%-18s%10.1f%10lld%12lld%14.4f\n", subject.name, measured.nanos_per_op, measured.gas_per_op,
                  subject.price, measured.nanos_per_op / static_cast<double>(subject.price));
      anchors.emplace_back(&subject, measured.nanos_per_op);
    } else {
      std::printf("%-18s%10.1f%10lld%12s%14s\n", subject.name, measured.nanos_per_op, measured.gas_per_op, "?", "?");
      unpriced.emplace_back(&subject, measured.nanos_per_op);
    }
  }

  // An anchor whose own price is far from its own cost cannot price anything
  // else, and BLS_G1_NEG is the case in point: it flips a sign bit on
  // compressed bytes and never decompresses.
  double loosest = 0;
  for (const auto& [subject, nanos] : anchors) {
    loosest = std::max(loosest, nanos / static_cast<double>(subject->price));
  }
  std::printf("\n%-18s%-18s%12s%10s\n", "instruction", "against", "implied gas", "used");
  for (const auto& [subject, nanos] : unpriced) {
    for (const auto& [anchor, anchor_nanos] : anchors) {
      const double ratio = anchor_nanos / static_cast<double>(anchor->price);
      const bool used = ratio > loosest / 10.0;
      std::printf("%-18s%-18s%12.0f%10s\n", subject->name, anchor->name,
                  nanos / anchor_nanos * static_cast<double>(anchor->price), used ? "yes" : "no");
    }
  }

  std::printf("\n%-18s%14s%14s\n", "instruction", "low", "high");
  for (const auto& [subject, nanos] : unpriced) {
    double low = 1e300;
    double high = 0;
    for (const auto& [anchor, anchor_nanos] : anchors) {
      const double ratio = anchor_nanos / static_cast<double>(anchor->price);
      if (ratio <= loosest / 10.0) {
        continue;
      }
      const double implied = nanos / anchor_nanos * static_cast<double>(anchor->price);
      low = std::min(low, implied);
      high = std::max(high, implied);
    }
    std::printf("%-18s%14.0f%14.0f\n", subject->name, low, high);
  }

  // PATH7 is two prices, so it needs a line rather than a bracket. Same fit
  // the Rust half reports, so the two halves can be compared without either
  // of them being reduced to arithmetic done by hand somewhere else.
  auto nanos_for = [&unpriced](const char* name) -> double {
    for (const auto& [subject, nanos] : unpriced) {
      if (std::string(subject->name) == name) {
        return nanos;
      }
    }
    return -1;
  };
  const double d1 = nanos_for("POSEIDON2_PATH7_D1");
  const double d12 = nanos_for("POSEIDON2_PATH7_D12");
  const double d32 = nanos_for("POSEIDON2_PATH7_D32");
  if (d1 > 0 && d12 > 0 && d32 > 0) {
    std::printf("\nPOSEIDON2_PATH7, as a base plus a per-level cost:\n");
    std::printf("%-26s%12s%12s%14s\n", "fitted over", "base gas", "gas/level", "at depth 12");
    const std::pair<const char*, std::pair<std::pair<int, double>, std::pair<int, double>>> fits[] = {
        {"depth 1 and 12", {{1, d1}, {12, d12}}},
        {"depth 12 and 32", {{12, d12}, {32, d32}}},
        {"depth 1 and 32 (widest)", {{1, d1}, {32, d32}}},
    };
    for (const auto& [label, pair] : fits) {
      const auto& [lo, hi] = pair;
      double lo_base = 1e300, hi_base = -1e300, lo_level = 1e300, hi_level = 0;
      for (const auto& [anchor, anchor_nanos] : anchors) {
        const double ratio = anchor_nanos / static_cast<double>(anchor->price);
        if (ratio <= loosest / 10.0) {
          continue;
        }
        const auto gas = [&](double ns) { return ns / anchor_nanos * static_cast<double>(anchor->price); };
        const double level = (gas(hi.second) - gas(lo.second)) / static_cast<double>(hi.first - lo.first);
        const double base = gas(lo.second) - level * lo.first;
        lo_base = std::min(lo_base, base);
        hi_base = std::max(hi_base, base);
        lo_level = std::min(lo_level, level);
        hi_level = std::max(hi_level, level);
      }
      char base_cell[64], level_cell[64], twelve_cell[64];
      std::snprintf(base_cell, sizeof(base_cell), "%.0f..%.0f", lo_base, hi_base);
      std::snprintf(level_cell, sizeof(level_cell), "%.0f..%.0f", lo_level, hi_level);
      std::snprintf(twelve_cell, sizeof(twelve_cell), "%.0f..%.0f", lo_base + 12 * lo_level,
                    hi_base + 12 * hi_level);
      std::printf("%-26s%12s%12s%14s\n", label, base_cell, level_cell, twelve_cell);
    }
  }
  return 0;
}
