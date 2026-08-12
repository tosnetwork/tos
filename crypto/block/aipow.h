/*
    Copyright (C) 2025-2026  TOS Network.

    Licensed under the GNU General Public License v3.0.
*/
#pragma once
#include "common/refint.h"
#include "block/mc-config.h"

namespace block {
namespace aipow {

/*
 * The single shared AIPoW epoch-mint derivation (Phase C, W4.4).
 *
 * This is the fork-critical amount path: at masterchain settlement the collator
 * ORIGINATES an epoch mint to the settlement account, and validate-query must
 * re-derive a byte-identical amount or the block is rejected. To avoid the
 * produce/check drift hazard, the amount is computed by ONE pure function here,
 * called identically by both the collator (to produce) and validate-query (to
 * check). It reads consensus state only -- the AIPoW config params, the
 * settlement ledger cursor, the committed organic value, and the block's
 * gen_utime -- and uses the same 257-bit integer type + muldiv the VM uses, so
 * overflow/rounding are identical on every build and architecture.
 *
 * Forbidden here (each a fork source): floating point, wall-clock/OS time,
 * RNG, unordered iteration, platform-dependent integer width, node-local state.
 */

// The tagged per-block decision. Skip advances the cursor with zero mint (D5);
// Mint mints `amount` to the settlement for `epoch`.
enum class EpochSettlementKind { NoSettlement, Skip, Mint };

struct EpochSettlement {
  EpochSettlementKind kind{EpochSettlementKind::NoSettlement};
  td::uint32 epoch{0};
  td::RefInt256 amount;  // non-null only when kind == Mint

  bool is_none() const {
    return kind == EpochSettlementKind::NoSettlement;
  }
  bool is_skip() const {
    return kind == EpochSettlementKind::Skip;
  }
  bool is_mint() const {
    return kind == EpochSettlementKind::Mint;
  }

  static EpochSettlement none() {
    return {};
  }
  static EpochSettlement skip(td::uint32 epoch) {
    return {EpochSettlementKind::Skip, epoch, {}};
  }
  static EpochSettlement mint(td::uint32 epoch, td::RefInt256 amount) {
    return {EpochSettlementKind::Mint, epoch, std::move(amount)};
  }
};

// The settlement ledger cursor (the fields the derivation reads from the
// settlement account's state; see the W4.1 layout).
struct SettlementCursor {
  td::uint32 next_epoch{0};      // the epoch to settle
  td::RefInt256 minted_total;    // cumulative AIPoW minted so far (nanotomis)
  td::uint32 epoch_seconds{0};   // epoch length (for the skip deadline)
  td::uint32 register_grace{0};  // grace after an epoch ends before it may be skipped
};

// The per-epoch pool from the committed organic value, per the arithmetic
// contract (all 257-bit, floor rounding, no floats):
//   pool = min(schedule_cap, max(cold_start_floor, floor(organic * k_num / k_den)))
// Returns a non-negative RefInt256, or a null ref (fail closed) on any broken
// input -- k_den == 0, a null/invalid organic value, null/invalid clamp fields,
// or a 257-bit overflow -- which the caller treats as "no mint".
td::RefInt256 compute_epoch_pool(const AipowConfig& cfg, const td::RefInt256& organic_settled_value);

// The full per-block epoch-settlement decision. Pure over consensus inputs.
//   * has_valid_commitment: the cursor epoch has a registration whose commitment
//     the caller resolved and verified (final + code-hash + tuple) -- this
//     function does not itself resolve accounts; that (deterministic) resolution
//     is the caller's job.
//   * organic_settled_value: the committed organic value of that commitment.
//   * gen_utime: the block's consensus time (never the node clock).
// Returns Mint (pool clamped to the remaining supply cap; terminal NoSettlement
// once the cap is exhausted), Skip (unregistered epoch past its grace deadline),
// or NoSettlement (nothing due this block).
EpochSettlement compute_epoch_mint(const AipowConfig& cfg, const AipowLimits& limits,
                                   const SettlementCursor& cursor, bool has_valid_commitment,
                                   const td::RefInt256& organic_settled_value, td::uint32 gen_utime);

}  // namespace aipow
}  // namespace block
