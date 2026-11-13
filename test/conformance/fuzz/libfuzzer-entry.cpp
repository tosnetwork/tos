// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// libFuzzer entry of the differential driver: the fuzzer input is the choice stream of the generator, so
// libFuzzer's byte mutations become structured mutations of the context. Configured from the environment:
//     CONFORMANCE_FUZZ_HARNESS    vm (default) or txn
//     CONFORMANCE_FUZZ_REFERENCE  reference library (required)
//     CONFORMANCE_FUZZ_TARGET     target library (required)
//     CONFORMANCE_FUZZ_SEEDS      seed fixture file or directory (optional; required for txn)
//     CONFORMANCE_FUZZ_OUT        vectors directory for mismatch files (optional)
//     CONFORMANCE_FUZZ_ABORT      1: abort on the first mismatch so libFuzzer keeps the input
//     CONFORMANCE_FUZZ_EMIT       file: append the context of every input both libraries ran with equal
//                                 effects, one JSON line each (run over a corpus with -runs=0 to harvest it)
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "differ.h"
#include "generator.h"

namespace {

using namespace conformance::fuzz;

struct State {
  std::string harness = "vm";
  std::string out;
  bool abort_on_mismatch = false;
  Library reference;
  Library target;
  SeedPool pool;
  std::FILE *emit = nullptr;
};

State *state = nullptr;

std::string env(const char *name) {
  const char *value = std::getenv(name);
  return value == nullptr ? std::string() : std::string(value);
}

[[noreturn]] void fail(const std::string &why) {
  std::fprintf(stderr, "conformance-fuzz: %s\n", why.c_str());
  std::exit(2);
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  state = new State();
  if (auto harness = env("CONFORMANCE_FUZZ_HARNESS"); !harness.empty()) {
    state->harness = harness;
  }
  state->out = env("CONFORMANCE_FUZZ_OUT");
  state->abort_on_mismatch = env("CONFORMANCE_FUZZ_ABORT") == "1";
  if (auto path = env("CONFORMANCE_FUZZ_EMIT"); !path.empty()) {
    state->emit = std::fopen(path.c_str(), "a");
    if (state->emit == nullptr) {
      fail("cannot open " + path);
    }
  }
  const std::string reference = env("CONFORMANCE_FUZZ_REFERENCE");
  const std::string target = env("CONFORMANCE_FUZZ_TARGET");
  if (reference.empty() || target.empty()) {
    fail("CONFORMANCE_FUZZ_REFERENCE and CONFORMANCE_FUZZ_TARGET are required");
  }
  if (auto error = state->reference.open(reference); !error.empty()) {
    fail(error);
  }
  if (auto error = state->target.open(target); !error.empty()) {
    fail(error);
  }
  std::vector<std::string> seeds;
  if (auto path = env("CONFORMANCE_FUZZ_SEEDS"); !path.empty()) {
    seeds.push_back(path);
  }
  if (auto error = state->pool.load(state->harness, seeds); !error.empty()) {
    fail(error);
  }
  if (auto error = check_generator(state->harness, state->pool); !error.empty()) {
    fail(error);
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  ByteChoices choices(data, size);
  Case c;
  if (!generate(state->harness, choices, state->pool, c).empty()) {
    return 0;
  }
  const std::string text = c.context.dump();
  const Comparison comparison =
      compare_effects(state->reference.run(state->harness, text), state->target.run(state->harness, text));
  if (comparison.verdict == Verdict::Equal && state->emit != nullptr) {
    std::fprintf(state->emit, "%s\n", text.c_str());
    std::fflush(state->emit);
  }
  if (comparison.verdict != Verdict::Mismatch) {
    return 0;
  }
  if (!state->out.empty()) {
    MismatchRecord record{state->harness,
                          c.lineage,
                          0,
                          0,
                          &c.context,
                          text,
                          std::filesystem::path(state->reference.path()).filename().string(),
                          std::filesystem::path(state->target.path()).filename().string(),
                          &comparison};
    std::string error;
    if (write_mismatch(state->out, record, error).empty()) {
      fail(error);
    }
  }
  std::fprintf(stderr, "MISMATCH lineage %s\n", c.lineage.c_str());
  if (state->abort_on_mismatch) {
    std::abort();
  }
  return 0;
}
