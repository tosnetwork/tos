// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include "ext-message-work-budget.hpp"
#include "tos/tos-types.h"
#include "td/utils/port/Clocks.h"

namespace tos::validator {

// Explicit experimental admission profile. A quote must cover a complete attempt
// for every destination supported by this exact chain configuration, including
// parsing, state lookup and special/native execution. No release rate is inferred.
struct ExtMessageWorkProfile {
  RootHash config_root{RootHash::zero()};
  std::uint64_t capacity{0};
  std::uint64_t refill_units{0};
  std::uint64_t refill_interval_ns{0};
  std::uint64_t attempt_units{0};
  std::uint32_t max_bytes{0};
  std::uint32_t max_depth{0};
};

class ExtMessageWorkAdmission {
 public:
  static td::Result<std::unique_ptr<ExtMessageWorkAdmission>> create(ExtMessageWorkProfile profile) {
    auto now = td::Clocks::monotonic_nano();
    if (now < 0 || profile.capacity == 0 || profile.refill_units == 0 || profile.refill_interval_ns == 0 ||
        profile.attempt_units == 0 || profile.attempt_units > profile.capacity ||
        profile.max_bytes == 0 || profile.max_depth == 0) {
      return td::Status::Error("invalid external admission work profile");
    }
    return std::unique_ptr<ExtMessageWorkAdmission>(new ExtMessageWorkAdmission(std::move(profile), now));
  }

  bool supports(const RootHash& config_root, std::uint32_t max_bytes, std::uint32_t max_depth) const {
    return config_root == profile_.config_root && max_bytes <= profile_.max_bytes && max_depth <= profile_.max_depth;
  }

  bool try_consume() {
    const auto now = td::Clocks::monotonic_nano();
    return now >= 0 && budget_.try_consume(profile_.attempt_units, static_cast<std::uint64_t>(now));
  }

  std::uint64_t available() const {
    return budget_.available();
  }

 private:
  ExtMessageWorkAdmission(ExtMessageWorkProfile profile, std::uint64_t now)
      : profile_(std::move(profile)), budget_(profile_.capacity, profile_.refill_units,
                                           profile_.refill_interval_ns, now) {}
  const ExtMessageWorkProfile profile_;
  ExtMessageWorkBudget budget_;
};

}  // namespace tos::validator
