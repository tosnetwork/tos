/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <cstdint>

#include "td/utils/Status.h"

namespace tos::proofverify::detail {

// The simulation entry point must populate these observations from the same
// authenticated target and the real unpacked Account storage. The local clock
// only selects an estimation scenario.
struct SimulationContextObservations {
  std::uint32_t shard_time;
  std::uint32_t masterchain_time;
  std::uint64_t shard_end_lt;
  std::uint64_t masterchain_lt;
  std::uint64_t last_transaction_start_lt;
  std::uint64_t last_transaction_end_lt;
  bool account_exists;
};

struct SelfPaySimulationContext {
  std::uint32_t estimated_time;
  std::uint64_t estimated_block_start_lt;
  std::uint64_t estimated_transaction_lt;
};

enum class SimulationContextError {
  UnsupportedVersion = 1,
  InvalidTime = 2,
  InvalidAccountTimes = 3,
  LogicalTimeOverflow = 4,
};

td::Result<SelfPaySimulationContext> derive_self_pay_simulation_context(
    const SimulationContextObservations& observations, std::int64_t local_now, std::uint32_t global_version);

}  // namespace tos::proofverify::detail
