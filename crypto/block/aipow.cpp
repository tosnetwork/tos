/*
    Copyright (C) 2025-2026  TOS Network.

    Licensed under the GNU General Public License v3.0.
*/
#include "block/aipow.h"

namespace block {
namespace aipow {

// A RefInt256 is usable only when it is both non-null AND a valid bigint.
// td::muldiv (and other ops) do NOT return null on 257-bit overflow: they return
// a non-null ref to an *invalid* (NaN) bigint. Comparisons on an invalid bigint
// are deterministic but meaningless (its sgn is INT_MIN, so it compares as
// "less than" everything), so it must be rejected explicitly, not just via
// is_null(), or an overflowed pool would be silently clamped to the floor
// instead of producing "no mint".
static bool is_usable(const td::RefInt256& x) {
  return x.not_null() && x->is_valid();
}

td::RefInt256 compute_epoch_pool(const AipowConfig& cfg, const td::RefInt256& organic_settled_value) {
  // Fail closed on any broken input so the derivation is total and never mints
  // under an undefined config: a zero denominator, a missing/invalid organic
  // value, or missing/invalid clamp fields all yield null (no mint). A
  // governance-valid config (see check_aipow_config) always materializes a
  // positive schedule_cap and a non-negative cold_start_floor, so this never
  // fires in consensus -- it is the strict "broken config => null" guarantee.
  if (cfg.k_den == 0 || !is_usable(organic_settled_value) || !is_usable(cfg.schedule_cap) ||
      !is_usable(cfg.cold_start_floor)) {
    return {};
  }
  // floor(organic * k_num / k_den) in the 257-bit integer type. round_mode -1 is
  // round-to-negative-infinity (floor); for non-negative operands this is exact
  // truncation, fixed and identical on every build/arch. On 257-bit overflow
  // muldiv yields an INVALID bigint (not null), so reject via is_usable and
  // propagate "no mint".
  td::RefInt256 raw =
      td::muldiv(organic_settled_value, td::make_refint((long long)cfg.k_num), td::make_refint((long long)cfg.k_den), -1);
  if (!is_usable(raw)) {
    return {};
  }
  td::RefInt256 pool = raw;
  // The cold-start floor lifts a low pool; the schedule cap is the hard ceiling
  // and is applied last so the floor can never push the pool above the cap.
  // Both fields were validated as usable above.
  if (pool < cfg.cold_start_floor) {
    pool = cfg.cold_start_floor;
  }
  if (pool > cfg.schedule_cap) {
    pool = cfg.schedule_cap;
  }
  return pool;
}

EpochSettlement compute_epoch_mint(const AipowConfig& cfg, const AipowLimits& limits,
                                   const SettlementCursor& cursor, bool has_valid_commitment,
                                   const td::RefInt256& organic_settled_value, td::uint32 gen_utime) {
  td::uint32 epoch = cursor.next_epoch;

  if (has_valid_commitment) {
    td::RefInt256 pool = compute_epoch_pool(cfg, organic_settled_value);
    if (pool.is_null() || td::sgn(pool) <= 0) {
      // A broken config or a zero pool: nothing to mint this block.
      return EpochSettlement::none();
    }
    // Cumulative supply cap: clamp the pool to the remaining budget, and stop
    // issuing once it is exhausted. minted_total and total_cap are exact ledger
    // integers, so the comparison is deterministic.
    if (!is_usable(limits.total_cap) || !is_usable(cursor.minted_total)) {
      return EpochSettlement::none();
    }
    td::RefInt256 remaining = limits.total_cap - cursor.minted_total;
    if (!is_usable(remaining) || td::sgn(remaining) <= 0) {
      // Cap reached: AIPoW issuance has ended (terminal).
      return EpochSettlement::none();
    }
    if (pool > remaining) {
      pool = remaining;  // the final, partial epoch pool
    }
    return EpochSettlement::mint(epoch, std::move(pool));
  }

  // No valid commitment for the cursor epoch: once the epoch's grace deadline has
  // passed it is skipped with zero mint, so a rejected or absent commitment never
  // halts issuance (D5). The epoch [epoch] spans
  // [epoch*epoch_seconds, (epoch+1)*epoch_seconds); it is skippable once the
  // grace after its end has elapsed. The whole expression is evaluated in 64-bit:
  // `epoch` is promoted to uint64 BEFORE `+ 1` so that epoch == 0xffffffff does
  // not wrap to 0 in uint32 (which would collapse the deadline to register_grace
  // and diverge from the FunC 257-bit check).
  td::uint64 skippable_at =
      ((td::uint64)epoch + 1) * (td::uint64)cursor.epoch_seconds + (td::uint64)cursor.register_grace;
  if ((td::uint64)gen_utime >= skippable_at) {
    return EpochSettlement::skip(epoch);
  }
  return EpochSettlement::none();
}

}  // namespace aipow
}  // namespace block
