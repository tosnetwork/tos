// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// In-process differential execution: two shared libraries exporting the conformance C interface
// (ref/conformance-ref.h) run the same context and their effects are compared.
#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "generator.h"
#include "json.h"

namespace conformance::fuzz {

class Library {
 public:
  Library() = default;
  ~Library();
  Library(const Library &) = delete;
  Library &operator=(const Library &) = delete;

  // dlopen with local symbols, each library resolving its own definitions first, so two copies of the same
  // code (a reference and a mutated build of it) do not bind to each other. Returns an error text.
  std::string open(const std::string &path);
  bool has_harness(const std::string &harness) const;
  std::string info() const;
  std::string run(const std::string &harness, const std::string &context) const;
  const std::string &path() const {
    return path_;
  }
  void *handle() const {
    return handle_;
  }

 private:
  using RunFn = const char *(*)(const char *, const char *);
  using HasFn = int (*)(const char *);
  using InfoFn = const char *(*)();
  using FreeFn = void (*)(const char *);

  std::string take(const char *text) const;

  void *handle_ = nullptr;
  RunFn run_ = nullptr;
  HasFn has_ = nullptr;
  InfoFn info_ = nullptr;
  FreeFn free_ = nullptr;
  std::string path_;
};

enum class Verdict { Equal, BothRefused, Mismatch };

struct Comparison {
  Verdict verdict = Verdict::Equal;
  Json reference;  // parsed effects, or the raw text as a string when it is not JSON
  Json target;
};

// Effects are equal when they parse to the same JSON value. A refusal ({"harness_error": ...}) never equals
// an effect; two refusals agree whatever their wording.
Comparison compare_effects(const std::string &reference, const std::string &target);

struct MismatchRecord {
  std::string harness;
  std::string lineage;
  std::uint64_t seed = 0;
  std::uint64_t index = 0;
  const Json *context = nullptr;
  std::string canonical_context;
  std::string reference_name;
  std::string target_name;
  const Comparison *comparison = nullptr;
};

// Writes <root>/<harness>/inputs/fuzz-mismatches/<lineage>/<sha256 of the canonical context>.json.
// Returns the path written, or an empty string with `error` set.
std::string write_mismatch(const std::string &root, const MismatchRecord &record, std::string &error);

// The mismatch file body; runner/fuzz_process.py writes the same layout.
std::string mismatch_text(const MismatchRecord &record);

struct Tally {
  std::uint64_t cases = 0;
  std::uint64_t equal = 0;
  std::uint64_t both_refused = 0;
  std::uint64_t mismatched = 0;
  std::uint64_t generator_errors = 0;
  std::uint64_t files_written = 0;
  std::map<std::string, std::uint64_t> cases_by_lineage;
  std::map<std::string, std::uint64_t> mismatches_by_lineage;
  // The reference's outcomes: the vm exit code, the txn outcome, or "refused"; a coverage indication.
  std::map<std::string, std::uint64_t> reference_outcomes;
  double seconds = 0;

  void count_outcome(const Json &reference_effects);

  std::string summary_json(const std::string &harness, std::uint64_t seed) const;
};

}  // namespace conformance::fuzz
