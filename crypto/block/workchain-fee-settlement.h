#pragma once

#include <optional>

#include "block/block-auto.h"
#include "block/block.h"

namespace block {

static_assert(gen::UnoV2FeeSettlement::cons_tag[gen::UnoV2FeeSettlement::uno_v2_fee_settlement] == 0xb02c852dU);
static_assert(gen::UnoV2FeeSettlement::cons_tag[gen::UnoV2FeeSettlement::uno_v2_fee_settlement_payer] == 0x53574632U);
static_assert(gen::UnoV2NativeEffects::cons_tag[0] == 0x0bd47725U);
static_assert(gen::UnoV2NativeEffects::cons_tag[1] == 0x67e2d380U);

// Components remain separate even when their sum is unchanged. These amounts
// must be reconstructed from verified operations and the authenticated fee
// schedule; decoding or conservation alone never authorizes a principal debit.
struct WorkchainFeeSettlement {
  td::Bits256 custody, coordinator;
  td::RefInt256 state_fee, compute_fee, tip;
  // Explicit payer claim, independently reconstructed by the engine. Absence
  // keeps the legacy custody payer. Encoding alone never authorizes this field.
  std::optional<td::Bits256> compute_payer;
};

struct WorkchainFeeTotals {
  CurrencyCollection state, collected, total;
};

// Native membership check, NOT operation authorization. The registered engine
// must independently reconstruct this claim from the authenticated operation;
// replay compares it with the candidate. Third-party claims stay encodable so
// the attempted payment is rejected here, not confused with malformed framing.
inline td::Result<td::Bits256> workchain_compute_fee_payer(const WorkchainFeeSettlement& fees) {
  const auto payer = fees.compute_payer.value_or(fees.custody);
  if (payer != fees.custody && payer != fees.coordinator)
    return td::Status::Error(-7200, "aggregate fee payer outside authenticated roles");
  if (payer == fees.coordinator &&
      (fees.state_fee.is_null() || fees.tip.is_null() || td::cmp(fees.state_fee, 0) != 0 || td::cmp(fees.tip, 0) != 0))
    return td::Status::Error(-7200, "coordinator compute payment cannot redirect state fee or tip");
  return payer;
}

inline td::Result<WorkchainFeeTotals> checked_workchain_fee_totals(const WorkchainFeeSettlement& fees) {
  if (fees.custody == fees.coordinator) return td::Status::Error("fee settlement roles coincide");
  for (const auto* amount : {&fees.state_fee, &fees.compute_fee, &fees.tip}) {
    if (amount->is_null() || !(*amount)->is_valid() || !(*amount)->unsigned_fits_bits(120)) {
      return td::Status::Error("fee component exceeds native amount encoding");
    }
  }
  WorkchainFeeTotals result;
  result.state = CurrencyCollection(fees.state_fee);
  if (!CurrencyCollection::add(CurrencyCollection(fees.compute_fee), CurrencyCollection(fees.tip), result.collected) ||
      !result.collected.tomis->unsigned_fits_bits(120) ||
      !CurrencyCollection::add(result.state, result.collected, result.total) ||
      !result.total.tomis->unsigned_fits_bits(120) || result.total.is_zero()) {
    return td::Status::Error("fee sum exceeds native encoding or is empty");
  }
  return result;
}

inline td::Result<td::Ref<vm::Cell>> encode_workchain_fee_settlement(const WorkchainFeeSettlement& fees) {
  TRY_STATUS(checked_workchain_fee_totals(fees));
  vm::CellBuilder cb;
  if (fees.compute_payer) {
    cb.store_long(0x53574632, 32).store_bits(fees.custody.bits(), 256).store_bits(fees.coordinator.bits(), 256);
    for (const auto* amount : {&fees.state_fee, &fees.compute_fee, &fees.tip}) {
      if (!tlb::t_Tomis.store_integer_value(cb, **amount)) return td::Status::Error("cannot encode fee amount");
    }
    cb.store_ref(vm::CellBuilder().store_bits(fees.compute_payer->bits(),256).finalize());
    return cb.finalize();
  }
  cb.store_long(0xb02c852d, 32).store_bits(fees.custody.bits(), 256).store_bits(fees.coordinator.bits(), 256);
  for (const auto* amount : {&fees.state_fee, &fees.compute_fee, &fees.tip}) {
    if (!tlb::t_Tomis.store_integer_value(cb, **amount)) return td::Status::Error("cannot encode fee amount");
  }
  return cb.finalize();
}

struct WorkchainNativeEffectsView {
  td::Ref<vm::CellSlice> payout, transfers;
  std::optional<WorkchainFeeSettlement> fees;
};

// Explicit tagged union: absence of fees preserves the original wire bytes.
// Unknown tags never fall through to the legacy representation. Exceptions
// propagate to the provenance-aware caller; these bytes may be replay output
// or a candidate claim, and the parser cannot decide that provenance.
inline td::Result<WorkchainNativeEffectsView> decode_workchain_native_effects(td::Ref<vm::Cell> root) {
  if (root.is_null()) return td::Status::Error("missing native effects");
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special) return td::Status::Error("special native effects");
  switch (cs.prefetch_ulong(32)) {
    case 0x0bd47725: {
      gen::UnoV2NativeEffects::Record_uno_v2_native_effects legacy;
      if (!tlb::unpack_cell(root, legacy)) return td::Status::Error("invalid legacy native effects");
      return WorkchainNativeEffectsView{legacy.payout, legacy.transfers, std::nullopt};
    }
    case 0x67e2d380: {
      gen::UnoV2NativeEffects::Record_uno_v2_native_effects_fees current;
      if (!tlb::unpack_cell(root, current)) {
        return td::Status::Error("invalid fee-bearing native effects");
      }
      auto shape = vm::load_cell_slice_special(current.fees, special);
      if (special || !shape.have(32)) return td::Status::Error("invalid fee record");
      WorkchainFeeSettlement fees;
      if (shape.prefetch_ulong(32) == 0xb02c852d) {
        gen::UnoV2FeeSettlement::Record_uno_v2_fee_settlement record;
        if (!tlb::unpack_cell(current.fees, record)) return td::Status::Error("invalid legacy fee record");
        fees = {record.custody, record.coordinator, tlb::t_Tomis.as_integer(record.state_fee),
            tlb::t_Tomis.as_integer(record.compute_fee), tlb::t_Tomis.as_integer(record.tip)};
      } else if (shape.prefetch_ulong(32) == 0x53574632) {
        gen::UnoV2FeeSettlement::Record_uno_v2_fee_settlement_payer record;
        gen::UnoV2FeePayer::Record payer;
        if (!tlb::unpack_cell(current.fees, record) || !tlb::unpack_cell(record.compute_payer, payer))
          return td::Status::Error("invalid explicit fee payer record");
        fees = {record.custody, record.coordinator, tlb::t_Tomis.as_integer(record.state_fee),
            tlb::t_Tomis.as_integer(record.compute_fee), tlb::t_Tomis.as_integer(record.tip), payer.account};
      } else return td::Status::Error("unknown fee record");
      TRY_STATUS(checked_workchain_fee_totals(fees));
      return WorkchainNativeEffectsView{current.payout, current.transfers, std::move(fees)};
    }
    default:
      return td::Status::Error("unknown native effects version");
  }
}

}  // namespace block
