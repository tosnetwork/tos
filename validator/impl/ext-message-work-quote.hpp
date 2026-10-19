// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>

#include "td/utils/Status.h"

namespace tos::validator {

// Initial TVM gas bound for stop-on-accept external admission without precompiled dispatch.
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

// Full transaction execution only: node admission stops at ACCEPT and uses
// the initial bound above. ACCEPT can raise an ordinary account's limit to gas_max, bounded by the
// configured gas_limit. Initial credit is therefore not a complete-attempt
// bound. This remains a gas bound, not calibrated CPU work, and excludes the
// separately bounded instruction overshoot, parsing and state lookup.
inline td::Result<std::uint64_t> external_tvm_complete_gas_bound(std::uint64_t gas_limit,
                                                                 std::uint64_t special_gas_limit,
                                                                 std::uint64_t gas_credit,
                                                                 bool has_precompiled_contracts) {
  TRY_RESULT(initial,
             external_tvm_initial_gas_bound(gas_limit, special_gas_limit, gas_credit, has_precompiled_contracts));
  constexpr auto maximum = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  if (gas_limit > maximum) {
    return td::Status::Error("external admission complete gas exceeds supported VM range");
  }
  return std::max(gas_limit, initial);
}

}  // namespace tos::validator
