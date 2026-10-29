/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <limits>

#include "crypto/block/mc-config.h"
#include "lite-client/proof-verify/self-pay-simulation-context.h"

namespace tos::proofverify::detail {

td::Result<SelfPaySimulationContext> derive_self_pay_simulation_context(const SimulationContextObservations& o,
                                                                        std::int64_t local_now,
                                                                        std::uint32_t global_version) {
  if (global_version < 16) {
    return td::Status::Error(static_cast<int>(SimulationContextError::UnsupportedVersion),
                             "self-pay simulation requires version 16 or later");
  }
  if (local_now <= 0 || local_now > std::numeric_limits<std::uint32_t>::max() || o.shard_time == 0 ||
      o.masterchain_time == 0) {
    return td::Status::Error(static_cast<int>(SimulationContextError::InvalidTime),
                             "simulation time is outside the supported nonzero range");
  }
  if ((!o.account_exists && (o.last_transaction_start_lt != 0 || o.last_transaction_end_lt != 0)) ||
      o.last_transaction_start_lt > o.last_transaction_end_lt || o.last_transaction_end_lt > o.shard_end_lt) {
    return td::Status::Error(static_cast<int>(SimulationContextError::InvalidAccountTimes),
                             "account transaction times contradict the observed shard");
  }

  constexpr auto alignment = block::Config::get_lt_align();
  static_assert(alignment > 1);
  // The account end is already bounded by the shard end above.
  const auto lower_bound = std::max(o.shard_end_lt, o.masterchain_lt);
  const auto quotient = lower_bound / alignment;
  // Reserve one logical-time unit for the transaction after the aligned start.
  // This bounds both the increment and multiplication before performing either.
  constexpr auto maximum_start = std::numeric_limits<std::uint64_t>::max() - 1;
  if (quotient >= maximum_start / alignment) {
    return td::Status::Error(static_cast<int>(SimulationContextError::LogicalTimeOverflow),
                             "simulation logical time cannot advance safely");
  }
  const auto block_start = (quotient + 1) * alignment;
  const auto transaction_lt = block_start + 1;
  const auto time = std::max({o.shard_time, o.masterchain_time, static_cast<std::uint32_t>(local_now)});
  return SelfPaySimulationContext{time, block_start, transaction_lt};
}

}  // namespace tos::proofverify::detail
