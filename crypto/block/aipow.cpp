/*
    Copyright (C) 2025-2026  TOS Network.

    Licensed under the GNU General Public License v3.0.
*/
#include "block/aipow.h"

namespace block {
namespace aipow {

td::RefInt256 compute_epoch_pool(const AipowConfig& cfg, const td::RefInt256& organic_settled_value) {
  // A zero denominator or a missing organic value cannot produce a defined pool;
  // return null so the caller mints nothing (a governance-valid config never has
  // k_den == 0, but the derivation must still be total and deterministic).
  if (cfg.k_den == 0 || organic_settled_value.is_null()) {
    return {};
  }
  // floor(organic * k_num / k_den) in the 257-bit integer type. round_mode -1 is
  // round-to-negative-infinity (floor); for non-negative operands this is exact
  // truncation, fixed and identical on every build/arch. muldiv returns null on
  // overflow, which we propagate as "no mint".
  td::RefInt256 raw =
      td::muldiv(organic_settled_value, td::make_refint((long long)cfg.k_num), td::make_refint((long long)cfg.k_den), -1);
  if (raw.is_null()) {
    return {};
  }
  td::RefInt256 pool = raw;
  // The cold-start floor lifts a low pool; the schedule cap is the hard ceiling
  // and is applied last so the floor can never push the pool above the cap.
  if (cfg.cold_start_floor.not_null() && pool < cfg.cold_start_floor) {
    pool = cfg.cold_start_floor;
  }
  if (cfg.schedule_cap.not_null() && pool > cfg.schedule_cap) {
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
    if (limits.total_cap.is_null() || cursor.minted_total.is_null()) {
      return EpochSettlement::none();
    }
    td::RefInt256 remaining = limits.total_cap - cursor.minted_total;
    if (td::sgn(remaining) <= 0) {
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
  // grace after its end has elapsed. 64-bit arithmetic holds uint32*uint32 with
  // no overflow, matching the FunC skip check.
  td::uint64 skippable_at =
      (td::uint64)(epoch + 1) * (td::uint64)cursor.epoch_seconds + (td::uint64)cursor.register_grace;
  if ((td::uint64)gen_utime >= skippable_at) {
    return EpochSettlement::skip(epoch);
  }
  return EpochSettlement::none();
}

}  // namespace aipow
}  // namespace block
