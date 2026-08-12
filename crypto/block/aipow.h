/*
    Copyright (C) 2025-2026  TOS Network.

    Licensed under the GNU General Public License v3.0.
*/
#pragma once
#include "common/refint.h"
#include "common/bitstring.h"
#include "vm/cells.h"
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

/*
 * Canonical raw-parsers over the W4.1/W4.2 contract data cells (W4.5 part 1).
 *
 * The collator and validate-query resolve the settlement + commitment accounts
 * from consensus state and feed the parsed values into compute_epoch_mint via
 * ONE shared code path (this module), so there is no produce/check drift. The
 * parsers are strict: every field is fetched with a checked read and a parse
 * that runs short or malformed returns false (the caller mints nothing). The
 * account layout is additionally implied by the registry code-hash check the
 * caller performs before parsing.
 *
 * These are pure over the input cells: no account resolution, no config, no
 * time -- only bit-exact fetches, so every node parses identically.
 */

// The settlement account's ledger (the fields the derivation reads, W4.1 layout).
struct SettlementLedger {
  td::uint16 version{0};
  td::uint32 next_epoch{0};
  td::uint32 epoch_seconds{0};
  td::uint32 register_grace{0};
  td::int32 earner_workchain{0};
  td::uint16 immediate_bps{0};
  td::uint16 stream_epochs{0};
  td::uint32 mat_epoch_seconds{0};
  td::RefInt256 minted_total;
  td::RefInt256 total_cap;
  td::Ref<vm::Cell> distributor_code;
  td::Ref<vm::Cell> registrations;  // dict root cell (null when empty)
};

// A per-epoch registration recorded by the settlement (W4.1 pack_registration).
struct Registration {
  bool found{false};
  td::int32 commitment_workchain{0};
  td::Bits256 commitment_addr;  // the nominating commitment's account id
  td::Bits256 score_root;
  td::RefInt256 total_score;
  td::RefInt256 organic_settled_value;
  td::uint32 registered_at{0};
};

// The commitment's economic state (the fields the derivation verifies, W4.2 layout).
struct CommitmentState {
  td::uint16 version{0};
  td::uint8 status{0};  // 0 committed, 1 challenged, 2 final, 3 rejected
  td::uint64 epoch{0};
  td::Bits256 score_root;
  td::RefInt256 total_score;
  td::RefInt256 organic_settled_value;
};

// The AIPoW commitment `status == final` value (mirrors the FunC status::final).
constexpr td::uint8 kCommitmentStatusFinal = 2;

// Parse the settlement account data cell. Returns false on a short/malformed cell.
bool parse_settlement_ledger(td::Ref<vm::Cell> data, SettlementLedger& out);

// Look up the registration for `epoch` in the settlement's registrations dict
// (udict 32 -> ^record). Returns a record with found=false if absent, or on a
// malformed dict/record.
Registration find_registration(const td::Ref<vm::Cell>& registrations_root, td::uint32 epoch);

// Parse the commitment account data cell. Returns false on a short/malformed cell.
bool parse_commitment_state(td::Ref<vm::Cell> data, CommitmentState& out);

// True iff a resolved commitment authorizes the epoch's mint: the expected
// layout version, status == final, its epoch equals the settled `epoch` (the
// registration dict key), and every committed field exactly matches the recorded
// registration (score_root, total_score, organic). The caller must separately
// have verified the commitment account's code hash against the registry (that
// resolution is not pure over cells).
bool commitment_authorizes(const Registration& reg, const CommitmentState& commitment,
                           td::uint16 expected_commitment_version, td::uint32 epoch);

}  // namespace aipow
}  // namespace block
