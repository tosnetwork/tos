/*
    Copyright (C) 2025-2026  TOS Network.

    Licensed under the GNU General Public License v3.0.
*/
#include "block/aipow.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"
#include "vm/excno.hpp"
#include "block/block.h"
#include "block/block-parse.h"

namespace block {
namespace aipow {

// The settlement layout version this code understands (mirrors the FunC
// settlement_version). An unknown version fails closed (no mint), so native code
// never reinterprets a future settlement layout under v1 semantics (D9).
static constexpr td::uint16 kSettlementVersion = 1;

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
    // The amount arithmetic does not know the winner; derive_masterchain_epoch_mint
    // fills in winner_id/winner_workchain after selecting the min-address valid
    // candidate.
    return EpochSettlement::mint(epoch, std::move(pool), td::Bits256::zero(), 0);
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

bool parse_settlement_ledger(td::Ref<vm::Cell> data, SettlementLedger& out) {
  if (data.is_null()) {
    return false;
  }
  try {
  vm::CellSlice cs = vm::load_cell_slice(data);
  unsigned long long version, next_epoch, epoch_seconds, register_grace, challenge_window, immediate_bps,
      stream_epochs, mat_epoch_seconds;
  long long earner_workchain;
  // version:16 next_epoch:32 epoch_seconds:32 register_grace:32 challenge_window:32
  // earner_workchain:int8 immediate_bps:16 stream_epochs:16 mat_epoch_seconds:32
  // minted_total:Grams total_cap:Grams ^distributor_code registrations:HashmapE
  if (!(cs.fetch_uint_to(16, version) && cs.fetch_uint_to(32, next_epoch) &&
        cs.fetch_uint_to(32, epoch_seconds) && cs.fetch_uint_to(32, register_grace) &&
        cs.fetch_uint_to(32, challenge_window) && cs.fetch_int_to(8, earner_workchain) &&
        cs.fetch_uint_to(16, immediate_bps) && cs.fetch_uint_to(16, stream_epochs) &&
        cs.fetch_uint_to(32, mat_epoch_seconds))) {
    return false;
  }
  out.version = (td::uint16)version;
  out.next_epoch = (td::uint32)next_epoch;
  out.epoch_seconds = (td::uint32)epoch_seconds;
  out.register_grace = (td::uint32)register_grace;
  out.challenge_window = (td::uint32)challenge_window;
  out.earner_workchain = (td::int32)earner_workchain;
  out.immediate_bps = (td::uint16)immediate_bps;
  out.stream_epochs = (td::uint16)stream_epochs;
  out.mat_epoch_seconds = (td::uint32)mat_epoch_seconds;
  out.minted_total = block::tlb::t_Tomis.as_integer_skip(cs);
  out.total_cap = block::tlb::t_Tomis.as_integer_skip(cs);
  if (out.minted_total.is_null() || out.total_cap.is_null()) {
    return false;
  }
  // distributor_code is an unconditional ^Cell; registrations is a HashmapE (a
  // Maybe ^Cell) whose root ref is null when the dictionary is empty.
  if (!cs.fetch_ref_to(out.distributor_code)) {
    return false;
  }
  if (!cs.fetch_maybe_ref(out.registrations)) {
    return false;
  }
  return cs.empty_ext();  // no ignored remainder (strict, D9)
  } catch (vm::VmError&) {
    return false;  // a special/pruned/malformed cell is not a valid ledger
  }
}

// Parse a single candidate record body (workchain:int8 score_root:256
// total_score:128 organic:128 registered_at:32). Returns false if malformed.
static bool parse_candidate_record(vm::CellSlice& rec, EpochCandidate& out) {
  long long workchain;
  unsigned long long registered_at;
  if (!(rec.fetch_int_to(8, workchain) && rec.fetch_bits_to(out.score_root) &&
        rec.fetch_uint256_to(128, out.total_score) &&
        rec.fetch_uint256_to(128, out.organic_settled_value) &&
        rec.fetch_uint_to(32, registered_at))) {
    return false;
  }
  if (!rec.empty_ext()) {
    return false;  // trailing garbage
  }
  out.workchain = (td::int32)workchain;
  out.registered_at = (td::uint32)registered_at;
  return true;
}

std::vector<EpochCandidate> list_epoch_candidates(const td::Ref<vm::Cell>& registrations_root,
                                                  td::uint32 epoch) {
  std::vector<EpochCandidate> out;
  if (registrations_root.is_null()) {
    return out;  // no registrations
  }
  try {
    vm::Dictionary registrations{registrations_root, 32};
    td::BitArray<32> ekey;
    ekey.store_ulong(epoch);
    auto epoch_cell = registrations.lookup_ref(ekey);
    if (epoch_cell.is_null()) {
      return out;  // no candidates for this epoch
    }
    // The epoch cell is [ count:uint16 candidates:HashmapE(256 -> record) ].
    vm::CellSlice ecs = vm::load_cell_slice(epoch_cell);
    unsigned long long count;
    td::Ref<vm::Cell> cand_root;
    if (!ecs.fetch_uint_to(16, count) || !ecs.fetch_maybe_ref(cand_root) || !ecs.empty_ext() ||
        cand_root.is_null()) {
      return out;  // malformed or empty candidate set
    }
    // Enumerate the candidates dict in ascending account-id order, bounded
    // (MAX_CANDIDATES is 8 on-chain; the guard caps the walk generously).
    vm::Dictionary candidates{cand_root, 256};
    td::BitArray<256> key;
    bool ok = candidates.get_minmax_key(key.bits(), 256, /*fetch_max=*/false).not_null();
    for (int guard = 0; ok && guard < 64; guard++) {
      auto val = candidates.lookup(key);
      if (val.not_null()) {
        EpochCandidate c;
        c.account_id = key;
        vm::CellSlice rec = *val;
        if (parse_candidate_record(rec, c)) {
          out.push_back(std::move(c));
        }
        // A malformed record is skipped (it can never authorize a mint anyway).
      }
      td::BitArray<256> next = key;
      ok = candidates.lookup_nearest_key(next.bits(), 256, /*fetch_next=*/true).not_null();
      key = next;
    }
    return out;
  } catch (vm::VmError&) {
    // A malformed dict/record must never throw; return whatever parsed cleanly.
    return out;
  }
}

bool parse_commitment_state(td::Ref<vm::Cell> data, CommitmentState& out) {
  if (data.is_null()) {
    return false;
  }
  try {
  vm::CellSlice cs = vm::load_cell_slice(data);
  // version:16 committer:MsgAddress reviewer:MsgAddress status:8 epoch:64
  // window_deadline:64 review_deadline:64 commit_bond:Grams challenge_bond:Grams
  // ^[score_root methodology total_score organic] ^[challenger ...] ^[settlement]
  // The economic tuple is the first ref; the whole outer layout is consumed and
  // validated (strict, D9) so a noncanonical parent is rejected.
  unsigned long long version, status, epoch, window_deadline, review_deadline;
  if (!cs.fetch_uint_to(16, version)) {
    return false;
  }
  if (!block::tlb::t_MsgAddress.skip(cs) || !block::tlb::t_MsgAddress.skip(cs)) {
    return false;  // committer, reviewer
  }
  if (!(cs.fetch_uint_to(8, status) && cs.fetch_uint_to(64, epoch) &&
        cs.fetch_uint_to(64, window_deadline) && cs.fetch_uint_to(64, review_deadline))) {
    return false;
  }
  if (block::tlb::t_Tomis.as_integer_skip(cs).is_null() ||       // commit_bond
      block::tlb::t_Tomis.as_integer_skip(cs).is_null()) {       // challenge_bond
    return false;
  }
  out.version = (td::uint16)version;
  out.status = (td::uint8)status;
  out.epoch = epoch;
  out.window_deadline = window_deadline;
  // Exactly three refs (economic tuple, challenger, settlement) and no leftover
  // inline data after the bonds.
  if (cs.size_refs() != 3) {
    return false;
  }
  vm::CellSlice tcs = vm::load_cell_slice(cs.fetch_ref());  // economic tuple (ref 0)
  if (cs.size() != 0 || cs.size_refs() != 2) {
    return false;  // trailing inline bits, or an unexpected ref count
  }
  td::Bits256 methodology_hash;
  if (!(tcs.fetch_bits_to(out.score_root) && tcs.fetch_bits_to(methodology_hash) &&
        tcs.fetch_uint256_to(128, out.total_score) &&
        tcs.fetch_uint256_to(128, out.organic_settled_value))) {
    return false;
  }
  return tcs.empty_ext();  // the economic tuple ref is exactly these four fields
  } catch (vm::VmError&) {
    return false;
  }
}

bool commitment_authorizes(const EpochCandidate& candidate, const CommitmentState& commitment,
                           td::uint16 expected_commitment_version, td::uint32 epoch,
                           td::uint32 challenge_window) {
  if (commitment.version != expected_commitment_version) {
    return false;
  }
  if (commitment.status != kCommitmentStatusFinal) {
    return false;
  }
  if (commitment.epoch != (td::uint64)epoch) {
    return false;
  }
  if (commitment.score_root != candidate.score_root) {
    return false;
  }
  if (!is_usable(commitment.total_score) || !is_usable(candidate.total_score) ||
      td::cmp(commitment.total_score, candidate.total_score) != 0) {
    return false;
  }
  if (!is_usable(commitment.organic_settled_value) || !is_usable(candidate.organic_settled_value) ||
      td::cmp(commitment.organic_settled_value, candidate.organic_settled_value) != 0) {
    return false;
  }
  // Provenance floor (W4.7): the commitment's challenge window must have been open
  // for at least `challenge_window` (the settlement's deployed value) after the
  // candidate's settlement-recorded registration. window_deadline is a commitment
  // deploy parameter and untrusted on its own, but registered_at is the settlement's
  // own clock (the committer cannot backdate it), so requiring
  // window_deadline >= registered_at + challenge_window forces the challenge op to
  // have accepted disputes across a real, observable window -- a commitment that
  // closed its window early (to finalize instantly) is rejected. The window must
  // ALSO have elapsed relative to gen_utime; that check is in derive (it needs the
  // block's consensus time).
  if ((td::uint64)commitment.window_deadline <
      (td::uint64)candidate.registered_at + (td::uint64)challenge_window) {
    return false;
  }
  return true;
}

EpochSettlement derive_masterchain_epoch_mint(const MasterchainMintContext& ctx,
                                              const AccountResolver& resolve) {
  // Totality: a missing resolver is a caller programming error, not a state that
  // should abort consensus derivation -> fail closed. (The resolver itself must
  // be deterministic and read consensus state only; that is the caller's
  // contract, so a deterministic resolver exception is a deterministic reject on
  // every node, not a fork.)
  if (!resolve) {
    return EpochSettlement::none();
  }
  // The settlement account lives on the masterchain (workchain -1).
  ResolvedAccount settlement = resolve(-1, ctx.settlement_addr);
  if (!settlement.exists) {
    return EpochSettlement::none();
  }
  SettlementLedger ledger;
  if (!parse_settlement_ledger(settlement.data, ledger)) {
    return EpochSettlement::none();
  }
  // Fail closed on an unknown settlement layout version (D9): never reinterpret a
  // future layout under v1 semantics.
  if (ledger.version != kSettlementVersion) {
    return EpochSettlement::none();
  }

  SettlementCursor cursor;
  cursor.next_epoch = ledger.next_epoch;
  cursor.minted_total = ledger.minted_total;
  cursor.epoch_seconds = ledger.epoch_seconds;
  cursor.register_grace = ledger.register_grace;
  cursor.challenge_window = ledger.challenge_window;
  // Enforce BOTH caps: the config's declared hard limit (ConfigParam 92) AND the
  // settlement's OWN stored total_cap. Using the minimum makes ConfigParam 92 an
  // actual consensus issuance limit (not merely informational) while still never
  // exceeding the stored cap the FunC settle checks -- so a clamped mint always
  // passes the on-chain cap guard even if the two caps disagree.
  AipowLimits ledger_limits;
  ledger_limits.total_cap = ledger.total_cap;
  if (is_usable(ctx.limits.total_cap) && ledger_limits.total_cap.not_null() &&
      ctx.limits.total_cap < ledger_limits.total_cap) {
    ledger_limits.total_cap = ctx.limits.total_cap;
  }

  // Candidate selection (fixes the first-wins griefing): enumerate the bounded
  // candidate set for the cursor epoch in ASCENDING address order, resolve and
  // verify each, and pick the MIN-ADDRESS VALID finalized commitment. A bogus
  // nomination cannot exclude the genuine one (both are candidates) nor freeze
  // the epoch (an all-bogus set falls through to the skip path below).
  //
  // PROVENANCE (W4.7): the code-hash pin proves only that a candidate account runs
  // the audited commitment CODE, not that its finalization was legitimate. A
  // commitment's window_deadline is a deploy parameter, so it cannot be trusted on
  // its own. Provenance is therefore enforced against the settlement's OWN clock:
  // a candidate mints only if its commitment kept the challenge window open for a
  // full kAipowChallengeWindow after the settlement-recorded registration
  // (commitment_authorizes) AND that window has actually elapsed relative to the
  // block's gen_utime (the check below). Because the settlement records
  // registered_at with its own now() at nomination (which the committer cannot
  // backdate) and the mint waits out the window, a fabricated commitment is forced
  // to sit through a real, observable dispute window during which the
  // challenge/bond/reviewer mechanism can reject it -- it can no longer be
  // finalized instantly. (The reviewer policy that makes disputing economic, D10,
  // remains a separate launch gate. Dark => inert.)
  std::vector<EpochCandidate> candidates = list_epoch_candidates(ledger.registrations, cursor.next_epoch);
  for (const EpochCandidate& c : candidates) {  // ascending address order (min first)
    ResolvedAccount commitment = resolve(c.workchain, c.account_id);
    if (!(commitment.exists && commitment.code_hash == ctx.commitment_code_hash)) {
      continue;
    }
    CommitmentState cstate;
    if (!parse_commitment_state(commitment.data, cstate) ||
        !commitment_authorizes(c, cstate, ctx.expected_commitment_version, cursor.next_epoch,
                               cursor.challenge_window)) {
      continue;
    }
    // The challenge window must have ELAPSED on the block's consensus clock before
    // this candidate can mint. A candidate still inside its window is not yet a
    // valid winner (it may yet be challenged); it is skipped, and because the
    // settlement's challenge_window < register_grace the epoch is not skippable yet
    // either, so compute_epoch_mint(false) below returns NoSettlement (wait), never a
    // skip that would strand a soon-to-be-valid mint.
    if ((td::uint64)ctx.gen_utime < (td::uint64)c.registered_at + (td::uint64)cursor.challenge_window) {
      continue;
    }
    // The min-address valid candidate that has cleared its challenge window wins.
    EpochSettlement r = compute_epoch_mint(ctx.config, ledger_limits, cursor, true,
                                           c.organic_settled_value, ctx.gen_utime);
    if (r.is_mint()) {
      r.winner_id = c.account_id;
      r.winner_workchain = c.workchain;
    }
    return r;
  }

  // No valid candidate (an unregistered epoch, or one with only bogus
  // candidates): the cursor advances via a skip past the grace deadline (the
  // on-chain skip no longer refuses a registered epoch), else nothing is due.
  return compute_epoch_mint(ctx.config, ledger_limits, cursor, false, td::RefInt256{}, ctx.gen_utime);
}

bool build_masterchain_mint_context(const block::Config& config, td::uint32 gen_utime,
                                    MasterchainMintContext& out) {
  // Fail closed unless capAipow is set: dark by default, no mint path.
  if (!config.aipow_enabled()) {
    return false;
  }
  auto cfg = config.get_aipow_config();
  auto lim = config.get_aipow_limits();
  auto reg = config.get_aipow_registry();
  // A block that sets capAipow without a complete, valid AIPoW parameter set is
  // rejected at config-install time (check_aipow_config); here we still fail
  // closed so a partial/malformed config can never originate a mint.
  if (cfg.is_error() || lim.is_error() || reg.is_error()) {
    return false;
  }
  out.config = cfg.move_as_ok();
  out.limits = lim.move_as_ok();
  auto registry = reg.move_as_ok();
  out.settlement_addr = registry.settlement_addr;
  out.commitment_code_hash = registry.commitment_code_hash;
  out.expected_commitment_version = 1;  // the layout version the native path understands (D9)
  out.gen_utime = gen_utime;
  return true;
}

td::Ref<vm::Cell> build_settle_mint_message(const td::Bits256& settlement_addr, const td::Bits256& winner_id,
                                            const td::RefInt256& amount, td::uint64 created_lt,
                                            td::uint32 created_at) {
  if (amount.is_null() || !amount->is_valid() || td::sgn(amount) <= 0) {
    return {};
  }
  block::CurrencyCollection value{amount};
  vm::CellBuilder cb;
  td::Ref<vm::Cell> msg;
  // int_msg_info$0, src = -1:00..00 (the masterchain minter the settlement
  // authenticates), dest = -1:settlement, value = amount, body = winner id inline.
  if (!(cb.store_long_bool(6, 4)             // int_msg_info$0 ihr_disabled:1 bounce:1 bounced:0
        && cb.store_long_bool(0x4ff, 11)     // addr_std$10 anycast:none workchain_id:int8 = -1
        && cb.store_zeroes_bool(256)         //   src = -1:00..00
        && cb.store_long_bool(0x4ff, 11)     // addr_std$10 anycast:none workchain_id:int8 = -1
        && cb.store_bits_bool(settlement_addr.bits(), 256)  //   dest = -1:settlement
        && value.store(cb)                   // value:CurrencyCollection
        && cb.store_zeroes_bool(4 + 4)       // extra_flags:(VarUInteger 16) fwd_fee:Tomis
        && cb.store_long_bool((long long)created_lt, 64)   // created_lt:uint64
        && cb.store_long_bool(created_at, 32)              // created_at:uint32
        && cb.store_zeroes_bool(1)           // init:(Maybe) = nothing
        && cb.store_long_bool(0, 1)          // body:(Either X ^X) = left (inline)
        && cb.store_bits_bool(winner_id.bits(), 256)  // body = winner id (settle reads exactly this)
        && cb.finalize_to(msg))) {
    return {};
  }
  return msg;
}

}  // namespace aipow
}  // namespace block
