// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Context generation for the differential fuzz driver (docs/fuzz.md). A context is built from a stream of
// choices: a seeded pseudo-random stream for the deterministic loop, or the input bytes for libFuzzer, so the
// same generator serves both. vm contexts come from a TVM instruction grammar or from mutated seed fixtures;
// txn contexts are mutations of seed contexts that keep every cell decodable.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "json.h"

namespace conformance::fuzz {

class Choices {
 public:
  virtual ~Choices() = default;
  virtual std::uint64_t next() = 0;
  // Uniform enough in [0, n); 0 when n is 0.
  std::uint64_t below(std::uint64_t n) {
    return n == 0 ? 0 : next() % n;
  }
  bool chance(unsigned percent) {
    return below(100) < percent;
  }
};

// splitmix64 stream.
class SeededChoices final : public Choices {
 public:
  explicit SeededChoices(std::uint64_t seed) : state_(seed) {
  }
  std::uint64_t next() override;

 private:
  std::uint64_t state_;
};

// Reads the choices from fuzzer input, four bytes each; an exhausted input yields zeros.
class ByteChoices final : public Choices {
 public:
  ByteChoices(const std::uint8_t *data, std::size_t size) : data_(data), size_(size) {
  }
  std::uint64_t next() override;

 private:
  const std::uint8_t *data_;
  std::size_t size_;
  std::size_t pos_ = 0;
};

// The stream of case `index` of a campaign: independent of batching, so a case is reproduced from
// (seed, index) alone.
std::uint64_t case_seed(std::uint64_t campaign_seed, std::uint64_t index);

struct Seed {
  std::string lineage;  // the seed's family, or the file stem of a contexts file
  Json context;
};

class SeedPool {
 public:
  // Loads every context of `harness` from fixture files (<family>.jsonl with optional <family>.blobs.json,
  // blob references resolved), from contexts files (lines {"context": ...}), or from directories of either
  // (searched recursively for *.jsonl). Returns an error text, empty on success.
  std::string load(const std::string &harness, const std::vector<std::string> &paths);
  const std::vector<Seed> &seeds() const {
    return seeds_;
  }

 private:
  std::vector<Seed> seeds_;
};

struct Case {
  std::string lineage;  // seed lineage, or "grammar" for a context built from the grammar alone
  Json context;
};

// Whether contexts of `harness` can be generated from `pool`: an error text (unknown harness, txn without
// seeds), empty when they can.
std::string check_generator(const std::string &harness, const SeedPool &pool);

// Builds one context; an error text means this case could not be built (the caller moves on), empty on
// success.
std::string generate(const std::string &harness, Choices &choices, const SeedPool &pool, Case &out);

// Lowercase hex SHA-256 of the canonical context text: the name of its mismatch file.
std::string context_digest(const std::string &canonical_context);

}  // namespace conformance::fuzz
