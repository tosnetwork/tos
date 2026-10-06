// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>

#include "td/utils/Status.h"

namespace tos::validator {

// Initial TVM gas bound for external transactions without precompiled dispatch.
// Before destination classification, include special-account execution: its
// initial gas_limit may already equal special_gas_limit, and VmState adds credit.
// This is not a CPU quote: parsing, lookup and instruction overshoot still need
// independently calibrated bounds. Custom execution engines are out of scope.
// The caller must derive the precompiled-config flag from the same snapshot:
// native implementations and TVM fallback cannot use this ordinary bound.
inline td::Result<std::uint64_t> external_tvm_initial_gas_bound(std::uint64_t gas_limit,
                                                               std::uint64_t special_gas_limit,
                                                               std::uint64_t gas_credit,
                                                               bool has_precompiled_contracts) {
  if (has_precompiled_contracts) {
    return td::Status::Error("external admission precompiled execution profile is not calibrated");
  }
  constexpr auto maximum = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  const auto ordinary = std::min(gas_limit, gas_credit);
  const auto special_credit = std::min(special_gas_limit, gas_credit);
  if (ordinary > maximum || special_gas_limit > maximum || special_credit > maximum - special_gas_limit) {
    return td::Status::Error("external admission initial gas exceeds supported VM range");
  }
  return std::max(ordinary, special_gas_limit + special_credit);
}

}  // namespace tos::validator
