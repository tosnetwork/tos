// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Deterministic differential fuzz loop (docs/fuzz.md):
//     conformance-fuzz --harness vm --reference <lib> --target <lib> [--seeds <path>]... [--cases N]
//                      [--seed S] [--start K] [--out <vectors dir>] [--max-files M] [--time-limit SEC]
//                      [--expect-mismatch] [--summary <file>]
//     conformance-fuzz --harness vm --emit [--seeds <path>]... [--cases N] [--seed S] [--start K]
// Case i of a campaign is generated from (seed, i) alone, so --emit prints exactly the contexts the loop runs
// (one {"index", "lineage", "context"} line each) for drivers that talk to command-line targets.
// Exit status: 0 when the campaign agrees (with --expect-mismatch: when it found a mismatch), 1 otherwise,
// 2 on a usage or setup error.
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#include "differ.h"
#include "generator.h"

namespace {

using namespace conformance::fuzz;

constexpr std::uint64_t kMaxCases = 100000000;
constexpr int kReportedMismatches = 20;

struct Options {
  std::string harness;
  std::string reference;
  std::string target;
  std::vector<std::string> seeds;
  std::uint64_t cases = 1000;
  std::uint64_t seed = 1;
  std::uint64_t start = 0;
  std::string out;
  std::uint64_t max_files = 1000;
  double time_limit = 0;
  bool expect_mismatch = false;
  bool emit = false;
  std::string summary;
};

// The context being run, for the fatal-signal report. Written only between cases.
const std::string *current_context = nullptr;
std::uint64_t current_index = 0;

void write_all(const char *text, std::size_t size) {
  while (size > 0) {
    const ssize_t done = ::write(STDERR_FILENO, text, size);
    if (done <= 0) {
      return;
    }
    text += done;
    size -= static_cast<std::size_t>(done);
  }
}

extern "C" void on_fatal_signal(int sig) {
  static const char head[] = "\nconformance-fuzz: fatal signal while running case ";
  write_all(head, sizeof head - 1);
  char digits[24];
  int n = 0;
  std::uint64_t v = current_index;
  do {
    digits[n++] = static_cast<char>('0' + v % 10);
    v /= 10;
  } while (v != 0 && n < 23);
  while (n > 0) {
    write_all(&digits[--n], 1);
  }
  static const char mid[] = "; context:\n";
  write_all(mid, sizeof mid - 1);
  if (current_context != nullptr) {
    write_all(current_context->data(), current_context->size());
  }
  write_all("\n", 1);
  std::signal(sig, SIG_DFL);
  std::raise(sig);
}

bool parse_u64(const char *text, std::uint64_t &out) {
  if (text == nullptr || *text == '\0') {
    return false;
  }
  char *end = nullptr;
  errno = 0;
  const unsigned long long value = std::strtoull(text, &end, 10);
  if (errno != 0 || end == nullptr || *end != '\0' || text[0] == '-') {
    return false;
  }
  out = value;
  return true;
}

int usage(const std::string &why) {
  std::cerr << "conformance-fuzz: " << why << "\n"
            << "usage: conformance-fuzz --harness <h> (--reference <lib> --target <lib> | --emit) [--seeds <path>]...\n"
            << "       [--cases N] [--seed S] [--start K] [--out <dir>] [--max-files M] [--time-limit SEC]\n"
            << "       [--expect-mismatch] [--summary <file>]\n";
  return 2;
}

int parse_args(int argc, char **argv, Options &o) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto value = [&]() -> const char * { return i + 1 < argc ? argv[++i] : nullptr; };
    if (arg == "--harness" || arg == "--reference" || arg == "--target" || arg == "--seeds" || arg == "--out" ||
        arg == "--summary") {
      const char *v = value();
      if (v == nullptr) {
        return usage(arg + " needs a value");
      }
      if (arg == "--harness") {
        o.harness = v;
      } else if (arg == "--reference") {
        o.reference = v;
      } else if (arg == "--target") {
        o.target = v;
      } else if (arg == "--seeds") {
        o.seeds.emplace_back(v);
      } else if (arg == "--out") {
        o.out = v;
      } else {
        o.summary = v;
      }
    } else if (arg == "--cases" || arg == "--seed" || arg == "--start" || arg == "--max-files" ||
               arg == "--time-limit") {
      std::uint64_t number = 0;
      if (!parse_u64(value(), number)) {
        return usage(arg + " needs a non-negative integer");
      }
      if (arg == "--cases") {
        o.cases = number;
      } else if (arg == "--seed") {
        o.seed = number;
      } else if (arg == "--start") {
        o.start = number;
      } else if (arg == "--max-files") {
        o.max_files = number;
      } else {
        o.time_limit = static_cast<double>(number);
      }
    } else if (arg == "--expect-mismatch") {
      o.expect_mismatch = true;
    } else if (arg == "--emit") {
      o.emit = true;
    } else {
      return usage("unknown argument " + arg);
    }
  }
  if (o.harness.empty()) {
    return usage("--harness is required");
  }
  if (o.cases == 0 || o.cases > kMaxCases) {
    return usage("--cases must be within 1.." + std::to_string(kMaxCases));
  }
  if (o.seed > static_cast<std::uint64_t>(INT64_MAX) || o.start > static_cast<std::uint64_t>(INT64_MAX) - o.cases) {
    return usage("--seed and --start + --cases must fit 63 bits");
  }
  if (!o.emit && (o.reference.empty() || o.target.empty())) {
    return usage("--reference and --target are required unless --emit is given");
  }
  return 0;
}

int emit(const Options &o, const SeedPool &pool) {
  std::ios::sync_with_stdio(false);
  std::string line;
  for (std::uint64_t i = o.start; i < o.start + o.cases; ++i) {
    SeededChoices choices(case_seed(o.seed, i));
    Case c;
    Json record = Json::object();
    record.set("index", Json::integer(static_cast<std::int64_t>(i)));
    if (auto error = generate(o.harness, choices, pool, c); !error.empty()) {
      record.set("error", Json::string(error));
    } else {
      record.set("lineage", Json::string(c.lineage));
      record.set("context", std::move(c.context));
    }
    line.clear();
    record.dump_to(line);
    std::cout << line << '\n';
  }
  std::cout.flush();
  return std::cout ? 0 : 2;
}

int campaign(const Options &o, const SeedPool &pool) {
  Library reference;
  Library target;
  if (auto error = reference.open(o.reference); !error.empty()) {
    std::cerr << "conformance-fuzz: " << error << '\n';
    return 2;
  }
  if (auto error = target.open(o.target); !error.empty()) {
    std::cerr << "conformance-fuzz: " << error << '\n';
    return 2;
  }
  if (!reference.has_harness(o.harness) || !target.has_harness(o.harness)) {
    std::cerr << "conformance-fuzz: a library does not provide harness " << o.harness << '\n';
    return 2;
  }
  if (reference.handle() == target.handle()) {
    std::cerr << "conformance-fuzz: note: reference and target are one loaded instance\n";
  }
  std::cerr << "reference " << reference.info() << "\ntarget    " << target.info() << '\n';
  std::signal(SIGSEGV, on_fatal_signal);
  std::signal(SIGABRT, on_fatal_signal);
  std::signal(SIGBUS, on_fatal_signal);
  std::signal(SIGFPE, on_fatal_signal);
  std::signal(SIGILL, on_fatal_signal);

  Tally tally;
  int reported = 0;
  const auto began = std::chrono::steady_clock::now();
  std::string text;
  const std::string reference_name = std::filesystem::path(o.reference).filename().string();
  const std::string target_name = std::filesystem::path(o.target).filename().string();
  for (std::uint64_t i = o.start; i < o.start + o.cases; ++i) {
    if (o.time_limit > 0 && (i - o.start) % 256 == 0) {
      const std::chrono::duration<double> spent = std::chrono::steady_clock::now() - began;
      if (spent.count() > o.time_limit) {
        std::cerr << "conformance-fuzz: time limit reached after " << tally.cases << " cases\n";
        break;
      }
    }
    SeededChoices choices(case_seed(o.seed, i));
    Case c;
    ++tally.cases;
    if (auto error = generate(o.harness, choices, pool, c); !error.empty()) {
      ++tally.generator_errors;
      continue;
    }
    ++tally.cases_by_lineage[c.lineage];
    text.clear();
    c.context.dump_to(text);
    current_index = i;
    current_context = &text;
    const std::string ref_effects = reference.run(o.harness, text);
    const std::string target_effects = target.run(o.harness, text);
    current_context = nullptr;
    const Comparison comparison = compare_effects(ref_effects, target_effects);
    tally.count_outcome(comparison.reference);
    if (comparison.verdict == Verdict::Equal) {
      ++tally.equal;
      continue;
    }
    if (comparison.verdict == Verdict::BothRefused) {
      ++tally.both_refused;
      continue;
    }
    ++tally.mismatched;
    ++tally.mismatches_by_lineage[c.lineage];
    std::string written;
    if (!o.out.empty() && tally.files_written < o.max_files) {
      MismatchRecord record{o.harness, c.lineage,      o.seed,      i,          &c.context,
                            text,      reference_name, target_name, &comparison};
      std::string error;
      written = write_mismatch(o.out, record, error);
      if (written.empty()) {
        std::cerr << "conformance-fuzz: " << error << '\n';
        return 2;
      }
      ++tally.files_written;
    }
    if (reported < kReportedMismatches) {
      ++reported;
      std::cerr << "MISMATCH case " << i << " lineage " << c.lineage << (written.empty() ? "" : " -> " + written)
                << "\n  reference " << comparison.reference.dump().substr(0, 400) << "\n  target    "
                << comparison.target.dump().substr(0, 400) << '\n';
    }
  }
  const std::chrono::duration<double> spent = std::chrono::steady_clock::now() - began;
  tally.seconds = spent.count();
  const std::string summary = tally.summary_json(o.harness, o.seed);
  std::cout << summary << '\n';
  if (!o.summary.empty()) {
    std::ofstream out(o.summary);
    out << summary << '\n';
  }
  const std::uint64_t compared = tally.cases - tally.generator_errors;
  if (compared == 0) {
    std::cerr << "conformance-fuzz: no case was compared\n";
    return 1;
  }
  if (o.expect_mismatch) {
    return tally.mismatched > 0 ? 0 : 1;
  }
  return tally.mismatched == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char **argv) {
  Options options;
  if (int status = parse_args(argc, argv, options); status != 0) {
    return status;
  }
  SeedPool pool;
  if (auto error = pool.load(options.harness, options.seeds); !error.empty()) {
    std::cerr << "conformance-fuzz: " << error << '\n';
    return 2;
  }
  if (auto error = check_generator(options.harness, pool); !error.empty()) {
    std::cerr << "conformance-fuzz: " << error << '\n';
    return 2;
  }
  return options.emit ? emit(options, pool) : campaign(options, pool);
}
