/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <limits>

#include "lite-client/proof-verify/self-pay-simulation-context.h"

using namespace tos::proofverify::detail;

int main() {
  int checks = 0, failures = 0;
  auto check = [&](const char* name, bool ok) {
    ++checks;
    std::printf("SIMULATION_CONTEXT_CASE %s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok)
      ++failures;
  };
  auto refused = [&](const SimulationContextObservations& o, std::int64_t now, std::uint32_t version,
                     SimulationContextError expected) {
    auto result = derive_self_pay_simulation_context(o, now, version);
    return result.is_error() && result.error().code() == static_cast<int>(expected);
  };
  const SimulationContextObservations original{100, 110, 2000000, 4000000, 1000000, 1000002, true};
  auto result = derive_self_pay_simulation_context(original, 120, 16);
  check("explicit-time-and-distinct-transaction-lt", result.is_ok() && result.ok().estimated_time == 120 &&
                                                         result.ok().estimated_block_start_lt == 5000000 &&
                                                         result.ok().estimated_transaction_lt == 5000001);
  auto o = original;
  o.masterchain_time = 150;
  result = derive_self_pay_simulation_context(o, 120, 16);
  check("masterchain-time-floor", result.is_ok() && result.ok().estimated_time == 150);
  o = original;
  o.shard_time = 160;
  result = derive_self_pay_simulation_context(o, 120, 16);
  check("shard-time-floor", result.is_ok() && result.ok().estimated_time == 160);
  o = original;
  o.shard_end_lt = 8000000;
  result = derive_self_pay_simulation_context(o, 120, 16);
  check("aligned-shard-end-advances", result.is_ok() && result.ok().estimated_block_start_lt == 9000000 &&
                                          result.ok().estimated_transaction_lt == 9000001);
  o = original;
  o.masterchain_lt = 10000009;
  result = derive_self_pay_simulation_context(o, 120, 16);
  check("masterchain-lt-floor", result.is_ok() && result.ok().estimated_block_start_lt == 11000000);
  o = original;
  o.account_exists = false;
  o.last_transaction_start_lt = 0;
  o.last_transaction_end_lt = 0;
  check("absent-account-zero-history", derive_self_pay_simulation_context(o, 120, 16).is_ok());
  o.last_transaction_end_lt = 1;
  check("absent-account-history-refused", refused(o, 120, 16, SimulationContextError::InvalidAccountTimes));
  o = original;
  o.last_transaction_end_lt = o.last_transaction_start_lt - 1;
  check("end-before-start-refused", refused(o, 120, 16, SimulationContextError::InvalidAccountTimes));
  o = original;
  o.last_transaction_end_lt = o.shard_end_lt + 1;
  check("end-after-shard-refused", refused(o, 120, 16, SimulationContextError::InvalidAccountTimes));
  check("version15-refused", refused(original, 120, 15, SimulationContextError::UnsupportedVersion));
  check("version19-context-accepted", derive_self_pay_simulation_context(original, 120, 19).is_ok());
  check("zero-clock-refused", refused(original, 0, 16, SimulationContextError::InvalidTime));
  check("negative-clock-refused", refused(original, -1, 16, SimulationContextError::InvalidTime));
  const auto max_time = std::numeric_limits<std::uint32_t>::max();
  check("clock-overflow-refused",
        refused(original, std::int64_t(max_time) + 1, 16, SimulationContextError::InvalidTime));
  result = derive_self_pay_simulation_context(original, max_time, 16);
  check("maximum-clock-representable", result.is_ok() && result.ok().estimated_time == max_time);
  o = original;
  o.shard_time = 0;
  check("zero-shard-time-refused", refused(o, 120, 16, SimulationContextError::InvalidTime));
  o = original;
  o.masterchain_time = 0;
  check("zero-masterchain-time-refused", refused(o, 120, 16, SimulationContextError::InvalidTime));
  const auto max_lt = std::numeric_limits<std::uint64_t>::max();
  const auto last_aligned = max_lt / 1000000 * 1000000;
  o = original;
  o.masterchain_lt = last_aligned - 1;
  result = derive_self_pay_simulation_context(o, 120, 16);
  check("last-safe-alignment", result.is_ok() && result.ok().estimated_block_start_lt == last_aligned &&
                                   result.ok().estimated_transaction_lt == last_aligned + 1);
  o.masterchain_lt = last_aligned;
  check("next-alignment-overflow-refused", refused(o, 120, 16, SimulationContextError::LogicalTimeOverflow));
  o.masterchain_lt = max_lt;
  check("maximum-lt-refused", refused(o, 120, 16, SimulationContextError::LogicalTimeOverflow));
  std::printf("SIMULATION_CONTEXT_CHECKS %d FAILURES %d\n", checks, failures);
  return failures ? 1 : 0;
}
