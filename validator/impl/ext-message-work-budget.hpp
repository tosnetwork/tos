// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <cstdint>

#include "td/utils/logging.h"

namespace tos::validator {

// Actor-owned token bucket for charged admission attempts. Unlike byte occupancy,
// work is never returned when an attempt fails, completes, or is cancelled.
// The caller supplies a monotonic clock and a conservative per-attempt quote.
// Rate/profile selection and dispatch must use the same validated configuration.
class ExtMessageWorkBudget {
 public:
  ExtMessageWorkBudget(std::uint64_t capacity, std::uint64_t refill_units,
                       std::uint64_t refill_interval, std::uint64_t now)
      : capacity_(capacity), refill_units_(refill_units), refill_interval_(refill_interval),
        available_(capacity), last_refill_(now), last_observed_(now) {
    CHECK(capacity > 0 && refill_units > 0 && refill_interval > 0);
  }

  bool try_consume(std::uint64_t quote, std::uint64_t now) {
    // A malformed quote or clock must never turn into free dispatch.
    if (quote == 0 || quote > capacity_ || now < last_observed_) {
      return false;
    }
    last_observed_ = now;
    const auto periods = (now - last_refill_) / refill_interval_;
    if (periods != 0) {
      const auto missing = capacity_ - available_;
      // Saturate before multiplication. Advancing the clock cannot overflow:
      // periods * interval <= now - last_refill.
      if (periods > missing / refill_units_) {
        available_ = capacity_;
      } else {
        available_ += periods * refill_units_;
      }
      last_refill_ += periods * refill_interval_;
    }
    if (quote > available_) {
      return false;
    }
    available_ -= quote;
    return true;
  }

  std::uint64_t available() const {
    return available_;
  }

 private:
  const std::uint64_t capacity_;
  const std::uint64_t refill_units_;
  const std::uint64_t refill_interval_;
  std::uint64_t available_;
  std::uint64_t last_refill_;
  std::uint64_t last_observed_;
};

}  // namespace tos::validator
