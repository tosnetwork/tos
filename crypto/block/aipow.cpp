/*
    Copyright (C) 2025-2026  TOS Network.

    Licensed under the GNU General Public License v3.0.
*/
#include "block/aipow.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"
#include "block/block-parse.h"

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

bool parse_settlement_ledger(td::Ref<vm::Cell> data, SettlementLedger& out) {
  if (data.is_null()) {
    return false;
  }
  vm::CellSlice cs = vm::load_cell_slice(data);
  unsigned long long version, next_epoch, epoch_seconds, register_grace, immediate_bps, stream_epochs,
      mat_epoch_seconds;
  long long earner_workchain;
  // version:16 next_epoch:32 epoch_seconds:32 register_grace:32 earner_workchain:int8
  // immediate_bps:16 stream_epochs:16 mat_epoch_seconds:32 minted_total:Grams total_cap:Grams
  // ^distributor_code registrations:HashmapE
  if (!(cs.fetch_uint_to(16, version) && cs.fetch_uint_to(32, next_epoch) &&
        cs.fetch_uint_to(32, epoch_seconds) && cs.fetch_uint_to(32, register_grace) &&
        cs.fetch_int_to(8, earner_workchain) && cs.fetch_uint_to(16, immediate_bps) &&
        cs.fetch_uint_to(16, stream_epochs) && cs.fetch_uint_to(32, mat_epoch_seconds))) {
    return false;
  }
  out.version = (td::uint16)version;
  out.next_epoch = (td::uint32)next_epoch;
  out.epoch_seconds = (td::uint32)epoch_seconds;
  out.register_grace = (td::uint32)register_grace;
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
}

Registration find_registration(const td::Ref<vm::Cell>& registrations_root, td::uint32 epoch) {
  Registration reg;
  if (registrations_root.is_null()) {
    return reg;  // empty dictionary -> not found
  }
  vm::Dictionary dict{registrations_root, 32};
  td::BitArray<32> key;
  key.store_ulong(epoch);
  auto rec_ref = dict.lookup_ref(key);
  if (rec_ref.is_null()) {
    return reg;  // not found
  }
  vm::CellSlice rcs = vm::load_cell_slice(rec_ref);
  // commitment_addr:MsgAddress score_root:256 total_score:128 organic:128 registered_at:32
  tos::WorkchainId workchain;
  tos::StdSmcAddress addr;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(rcs, workchain, addr, false)) {
    return reg;  // a non-standard commitment address is unauthorized -> not found
  }
  reg.commitment_workchain = workchain;
  reg.commitment_addr = addr;
  unsigned long long registered_at;
  if (!(rcs.fetch_bits_to(reg.score_root) && rcs.fetch_uint256_to(128, reg.total_score) &&
        rcs.fetch_uint256_to(128, reg.organic_settled_value) && rcs.fetch_uint_to(32, registered_at))) {
    return reg;  // malformed record -> not found
  }
  if (!rcs.empty_ext()) {
    return reg;  // trailing garbage -> not found (strict)
  }
  reg.registered_at = (td::uint32)registered_at;
  reg.found = true;
  return reg;
}

bool parse_commitment_state(td::Ref<vm::Cell> data, CommitmentState& out) {
  if (data.is_null()) {
    return false;
  }
  vm::CellSlice cs = vm::load_cell_slice(data);
  // version:16 committer:MsgAddress reviewer:MsgAddress status:8 epoch:64 ...
  // The score_root/total_score/organic live in the first ref (^[score_root
  // methodology total_score organic]); the inline deadlines/bonds after `epoch`
  // are not needed, and refs are a separate stream from the data bits.
  unsigned long long version, status, epoch;
  if (!cs.fetch_uint_to(16, version)) {
    return false;
  }
  if (!block::tlb::t_MsgAddress.skip(cs) || !block::tlb::t_MsgAddress.skip(cs)) {
    return false;  // committer, reviewer
  }
  if (!(cs.fetch_uint_to(8, status) && cs.fetch_uint_to(64, epoch))) {
    return false;
  }
  out.version = (td::uint16)version;
  out.status = (td::uint8)status;
  out.epoch = epoch;
  if (cs.size_refs() < 1) {
    return false;
  }
  vm::CellSlice tcs = vm::load_cell_slice(cs.prefetch_ref(0));
  td::Bits256 methodology_hash;
  if (!(tcs.fetch_bits_to(out.score_root) && tcs.fetch_bits_to(methodology_hash) &&
        tcs.fetch_uint256_to(128, out.total_score) &&
        tcs.fetch_uint256_to(128, out.organic_settled_value))) {
    return false;
  }
  return tcs.empty_ext();  // the economic tuple ref is exactly these four fields
}

bool commitment_authorizes(const Registration& reg, const CommitmentState& commitment,
                           td::uint16 expected_commitment_version, td::uint32 epoch) {
  if (!reg.found) {
    return false;
  }
  if (commitment.version != expected_commitment_version) {
    return false;
  }
  if (commitment.status != kCommitmentStatusFinal) {
    return false;
  }
  if (commitment.epoch != (td::uint64)epoch) {
    return false;
  }
  if (commitment.score_root != reg.score_root) {
    return false;
  }
  if (!is_usable(commitment.total_score) || !is_usable(reg.total_score) ||
      td::cmp(commitment.total_score, reg.total_score) != 0) {
    return false;
  }
  if (!is_usable(commitment.organic_settled_value) || !is_usable(reg.organic_settled_value) ||
      td::cmp(commitment.organic_settled_value, reg.organic_settled_value) != 0) {
    return false;
  }
  return true;
}

EpochSettlement derive_masterchain_epoch_mint(const MasterchainMintContext& ctx,
                                              const AccountResolver& resolve) {
  // The settlement account lives on the masterchain (workchain -1).
  ResolvedAccount settlement = resolve(-1, ctx.settlement_addr);
  if (!settlement.exists) {
    return EpochSettlement::none();
  }
  SettlementLedger ledger;
  if (!parse_settlement_ledger(settlement.data, ledger)) {
    return EpochSettlement::none();
  }

  SettlementCursor cursor;
  cursor.next_epoch = ledger.next_epoch;
  cursor.minted_total = ledger.minted_total;
  cursor.epoch_seconds = ledger.epoch_seconds;
  cursor.register_grace = ledger.register_grace;
  // Enforce the cap against the settlement's OWN stored total_cap (what the FunC
  // settle checks), so a clamped mint always passes its cap guard. The config
  // AipowLimits.total_cap is the declared limit, validated to equal this at
  // activation.
  AipowLimits ledger_limits;
  ledger_limits.total_cap = ledger.total_cap;

  Registration reg = find_registration(ledger.registrations, cursor.next_epoch);
  if (reg.found) {
    // A registered epoch: resolve and verify the nominating commitment. Only a
    // genuine (code-hash-pinned) finalized commitment whose committed tuple
    // matches the registration authorizes the mint.
    ResolvedAccount commitment = resolve(reg.commitment_workchain, reg.commitment_addr);
    bool has_valid = false;
    if (commitment.exists && commitment.code_hash == ctx.commitment_code_hash) {
      CommitmentState cstate;
      if (parse_commitment_state(commitment.data, cstate) &&
          commitment_authorizes(reg, cstate, ctx.expected_commitment_version, cursor.next_epoch)) {
        has_valid = true;
      }
    }
    if (has_valid) {
      return compute_epoch_mint(ctx.config, ledger_limits, cursor, true, reg.organic_settled_value,
                                ctx.gen_utime);
    }
    // Registered but the commitment is invalid/unresolvable: no mint, and the
    // on-chain skip refuses a registered epoch (skip_registered), so the cursor
    // cannot advance this block.
    return EpochSettlement::none();
  }

  // Unregistered epoch: skip past the grace deadline, else nothing due.
  return compute_epoch_mint(ctx.config, ledger_limits, cursor, false, td::RefInt256{}, ctx.gen_utime);
}

}  // namespace aipow
}  // namespace block
