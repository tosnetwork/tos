// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include "ext-message-work-budget.hpp"
#include "validator/admission-work-profile.h"
#include "td/utils/port/Clocks.h"

namespace tos::validator {

class ExtMessageWorkAdmission {
 public:
  static td::Result<std::unique_ptr<ExtMessageWorkAdmission>> create(ExtMessageWorkProfile profile) {
    TRY_STATUS(profile.validate());
    auto now = td::Clocks::monotonic_nano();
    if (now < 0) {
      return td::Status::Error("external admission monotonic clock is unavailable");
    }
    return std::unique_ptr<ExtMessageWorkAdmission>(new ExtMessageWorkAdmission(std::move(profile), now));
  }

  td::Status update_profile(ExtMessageWorkProfile profile) {
    TRY_STATUS(profile.validate());
    if (profile.capacity != profile_.capacity || profile.refill_units != profile_.refill_units ||
        profile.refill_interval_ns != profile_.refill_interval_ns || profile.attempt_units != profile_.attempt_units ||
        profile.max_bytes != profile_.max_bytes || profile.max_depth != profile_.max_depth) {
      return td::Status::Error("external admission rate or cost changes require restart");
    }
    // Rebinding an explicitly reviewed configuration must not replenish tokens
    // or change the refill clock. Budget ownership survives configuration churn.
    profile_ = std::move(profile);
    return td::Status::OK();
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
  ExtMessageWorkProfile profile_;
  ExtMessageWorkBudget budget_;
};

}  // namespace tos::validator
