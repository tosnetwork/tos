// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <cstdint>

#include "td/utils/Status.h"
#include "tos/tos-types.h"

namespace tos::validator {

// Explicit experimental admission profile. A quote must cover a complete attempt
// for every destination supported by this exact chain configuration, including
// parsing, state lookup and special/native execution. No release rate is inferred.
struct ExtMessageWorkProfile {
  static td::Result<ExtMessageWorkProfile> parse(td::Slice text);
  RootHash config_root{RootHash::zero()};
  std::uint64_t capacity{0};
  std::uint64_t refill_units{0};
  std::uint64_t refill_interval_ns{0};
  std::uint64_t attempt_units{0};
  std::uint32_t max_bytes{0};
  std::uint32_t max_depth{0};

  td::Status validate() const {
    if (config_root.is_zero() || capacity == 0 || refill_units == 0 || refill_interval_ns == 0 || attempt_units == 0 ||
        attempt_units > capacity || max_bytes == 0 || max_depth == 0) {
      return td::Status::Error("invalid external admission work profile");
    }
    return td::Status::OK();
  }
};

}  // namespace tos::validator
