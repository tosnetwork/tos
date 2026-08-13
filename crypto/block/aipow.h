/*
    Copyright (C) 2025-2026  TOS Network.

    Licensed under the GNU General Public License v3.0.
*/
#pragma once
#include <functional>
#include <vector>
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
  td::RefInt256 amount;          // non-null only when kind == Mint
  td::Bits256 winner_id;         // Mint: the selected winning commitment's account id
  td::int32 winner_workchain{0}; // Mint: the winning commitment's workchain

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
    EpochSettlement s;
    s.kind = EpochSettlementKind::Skip;
    s.epoch = epoch;
    return s;
  }
  static EpochSettlement mint(td::uint32 epoch, td::RefInt256 amount, const td::Bits256& winner_id,
                              td::int32 winner_workchain) {
    EpochSettlement s;
    s.kind = EpochSettlementKind::Mint;
    s.epoch = epoch;
    s.amount = std::move(amount);
    s.winner_id = winner_id;
    s.winner_workchain = winner_workchain;
    return s;
  }
};

// The settlement ledger cursor (the fields the derivation reads from the
// settlement account's state; see the W4.1 layout).
struct SettlementCursor {
  td::uint32 next_epoch{0};       // the epoch to settle
  td::RefInt256 minted_total;     // cumulative AIPoW minted so far (nanotomis)
  td::uint32 epoch_seconds{0};    // epoch length (for the skip deadline)
  td::uint32 register_grace{0};   // grace after an epoch ends before it may be skipped
  td::uint32 challenge_window{0}; // the provenance floor (seconds); < register_grace
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
  td::uint32 challenge_window{0};
  td::int32 earner_workchain{0};
  td::uint16 immediate_bps{0};
  td::uint16 stream_epochs{0};
  td::uint32 mat_epoch_seconds{0};
  td::RefInt256 minted_total;
  td::RefInt256 total_cap;
  td::Ref<vm::Cell> distributor_code;
  td::Ref<vm::Cell> registrations;  // dict root cell (null when empty)
};

// One candidate nomination recorded by the settlement for an epoch (the account
// id is the candidate key; the tuple is what the commitment committed).
struct EpochCandidate {
  td::Bits256 account_id;   // the nominating commitment's account id (dict key)
  td::int32 workchain{0};
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
  td::uint64 window_deadline{0};  // unix; challenges accepted strictly before this
  td::Bits256 score_root;
  td::RefInt256 total_score;
  td::RefInt256 organic_settled_value;
};

// The AIPoW commitment `status == final` value (mirrors the FunC status::final).
constexpr td::uint8 kCommitmentStatusFinal = 2;

// The provenance floor (W4.7): the span (seconds) a candidate's challenge window
// must have been OPEN and then ELAPSED, measured from the settlement's trusted
// registration time, before its commitment may mint. This is what makes a real,
// observable dispute window mandatory: a commitment cannot backdate or shorten it,
// because its window_deadline is checked against the settlement-recorded
// registered_at (a clock the committer does not control), and the mint waits until
// the block's gen_utime is past registered_at + this span.
//
// The ACTUAL value is a settlement deploy parameter (SettlementCursor::challenge_window),
// which the derivation reads, so governance can tune it per settlement and tests can
// shrink it. This constant is only the recommended default the SDK deploys with. The
// deployed value MUST be strictly less than the settlement's register_grace (enforced
// in the settlement SDK's build_data), so a valid candidate always mints before its
// epoch becomes skippable.
constexpr td::uint32 kAipowChallengeWindow = 7u * 24 * 3600;  // 7 days (SDK default)

// Parse the settlement account data cell. Returns false on a short/malformed cell.
bool parse_settlement_ledger(td::Ref<vm::Cell> data, SettlementLedger& out);

// Enumerate the bounded candidate set recorded for `epoch`, in ASCENDING
// account-id (address) order -- the order the native path evaluates candidates
// to select the min-address valid one. Returns empty for an absent epoch or on a
// malformed dict/record (never throws). The set is bounded by MAX_CANDIDATES in
// the contract, so this is O(1).
std::vector<EpochCandidate> list_epoch_candidates(const td::Ref<vm::Cell>& registrations_root,
                                                  td::uint32 epoch);

// Parse the commitment account data cell. Returns false on a short/malformed cell.
bool parse_commitment_state(td::Ref<vm::Cell> data, CommitmentState& out);

// True iff a resolved commitment authorizes a candidate's mint: the expected
// layout version, status == final, its epoch equals the settled `epoch`, every
// committed field exactly matches the candidate (score_root, total_score,
// organic), AND its window_deadline covers registered_at + challenge_window (the
// provenance floor -- challenge_window is the settlement's deployed value). The
// caller must separately have verified the commitment account's code hash against
// the registry (that resolution is not pure over cells).
bool commitment_authorizes(const EpochCandidate& candidate, const CommitmentState& commitment,
                           td::uint16 expected_commitment_version, td::uint32 epoch,
                           td::uint32 challenge_window);

/*
 * The single shared masterchain epoch-mint decision (W4.5 part 2).
 *
 * This ties the parsers + authorization + compute_epoch_mint into ONE function
 * that both the collator (to produce the mint) and validate-query (to check it)
 * call, so the produce and check paths cannot drift. It is deterministic given
 * the account resolver is deterministic (the resolver reads consensus state
 * only). It does not touch value_flow / special messages -- it returns the
 * tagged decision + amount, which those consensus paths then apply/verify.
 */

// An account resolved from the masterchain state: its code cell hash and data
// cell. `exists` is false for a missing/uninitialized account.
struct ResolvedAccount {
  bool exists{false};
  td::Bits256 code_hash;   // hash of the account's code cell
  td::Ref<vm::Cell> data;  // the account's data cell
};

// Resolves an account by (workchain, account id) from the masterchain state.
// Provided by the collator/validator. CONTRACT: it MUST be deterministic (reads
// consensus state only) and MUST NOT throw over well-formed consensus state --
// derive is total/deterministic only under this contract. A deterministic
// resolver failure is a deterministic reject on every node (not a fork), and is
// the resolver's to signal (e.g. via an empty ResolvedAccount), not derive's to
// swallow -- masking a genuine state-access error would hide a real bug.
using AccountResolver = std::function<ResolvedAccount(td::int32 workchain, const td::Bits256& account_id)>;

// Immutable inputs to the decision, from the block's config.
struct MasterchainMintContext {
  AipowConfig config;
  AipowLimits limits;                       // ConfigParam 92: the declared hard supply cap
  td::Bits256 settlement_addr;              // ConfigParam 93 settlement_addr (masterchain)
  td::Bits256 commitment_code_hash;         // the expected AIPoW commitment code cell hash (registry)
  td::uint16 expected_commitment_version{1};
  td::uint32 gen_utime{0};                  // the block's consensus time
};

// Resolve the settlement account and, if the cursor epoch is registered, the
// registered commitment; verify the commitment (code hash + status final +
// version + tuple exactly matching the registration); then compute the epoch
// settlement.
//   * A registered epoch with a valid commitment -> Mint (pool clamped to the
//     settlement's own remaining cap, so the mint always passes the FunC settle
//     cap check).
//   * A registered epoch with an INVALID/unresolvable commitment -> NoSettlement
//     (the FunC skip refuses a registered epoch, so the cursor cannot advance
//     this block; matches the on-chain skip_registered guard).
//   * An unregistered epoch -> Skip past its grace deadline, else NoSettlement.
//   * A missing/malformed settlement account -> NoSettlement.
EpochSettlement derive_masterchain_epoch_mint(const MasterchainMintContext& ctx,
                                              const AccountResolver& resolve);

// Build the mint context from the block's config (ConfigParams 90/92/93) at
// gen_utime. Returns false -- fail closed, no mint -- when AIPoW is not enabled
// (capAipow off) or any required parameter is absent/malformed. Both the collator
// (produce) and validate-query (check) call THIS to build an identical context,
// so the two paths cannot drift in how they read config.
bool build_masterchain_mint_context(const block::Config& config, td::uint32 gen_utime,
                                    MasterchainMintContext& out);

// Build the canonical AIPoW settle mint message cell: a bounceable base-gram
// internal message from the masterchain minter -1:00..00 to `settlement_addr`
// carrying `amount` nanotomis, with the 256-bit `winner_id` as its inline body
// (exactly what the settlement's settle path reads). This is the SINGLE source of
// truth for the mint message bytes: the collator emits exactly this, and
// validate-query rebuilds it to locate the InMsg by hash in the block's InMsgDescr
// and exact-match it, so the produce and check paths agree byte-for-byte with no
// block-format field to carry it. Returns a null ref on a build failure.
td::Ref<vm::Cell> build_settle_mint_message(const td::Bits256& settlement_addr, const td::Bits256& winner_id,
                                            const td::RefInt256& amount, td::uint64 created_lt,
                                            td::uint32 created_at);

}  // namespace aipow
}  // namespace block
