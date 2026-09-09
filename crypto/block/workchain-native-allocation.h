#pragma once

#include "block/block-auto.h"
#include "block/block.h"
#include "block/workchain-participant-lt.h"
#include "block/workchain-fee-settlement.h"

namespace block {

// Post-admission accounting, not transfer authorization. The host must first
// reconstruct these effects from its single engine invocation. Closure and
// traversal budgets apply before this function; this scan is not admission.
// Sum each side before subtraction: a logical batch has no edge execution
// order. Checked subtraction proves that all outgoing value is funded by the
// credited old balance plus incoming allocations, independently per currency.
// Source, VM and builder exceptions propagate to the source-aware caller.
inline td::Result<CurrencyCollection> allocate_workchain_native_balance(
    const td::Bits256& account, const CurrencyCollection& credited,
    const gen::UnoV2HostEffects::Record& effects, std::uint64_t max_transfers, int extra_validation_cells) {
  if (extra_validation_cells <= 0) return td::Status::Error("invalid allocation validation budget");
  auto valid = [&](const CurrencyCollection& value) {
    return value.tomis.not_null() && value.tomis->is_valid() && value.tomis->unsigned_fits_bits(256) &&
           value.validate_extra(extra_validation_cells);
  };
  if (!valid(credited)) return td::Status::Error("invalid credited allocation balance");
  TRY_RESULT(native, decode_workchain_native_effects(effects.native));
  vm::Dictionary updates(effects.updates, 256), transfers(native.transfers, 32);
  if (updates.lookup_ref(account).is_null()) return td::Status::Error("allocation account absent from updates");
  CurrencyCollection incoming(0), outgoing(0);
  std::uint64_t index = 0;
  td::Bits256 previous_from, previous_to;
  if (!transfers.check_for_each([&](td::Ref<vm::CellSlice> leaf, td::ConstBitPtr key, int bits) {
        if (index >= max_transfers) return false;
        if (bits != 32 || key.get_uint(32) != index || leaf->size_ext() != 0x10000) return false;
        gen::UnoV2NativeTransfer::Record transfer;
        CurrencyCollection value;
        if (!::tlb::unpack_cell(leaf->prefetch_ref(), transfer) || transfer.source == transfer.destination ||
            !value.unpack(transfer.value) || !valid(value) || value.is_zero()) return false;
        if (index != 0 && !(previous_from < transfer.source ||
            (previous_from == transfer.source && previous_to < transfer.destination))) return false;
        if (updates.lookup_ref(transfer.source).is_null() || updates.lookup_ref(transfer.destination).is_null()) return false;
        previous_from = transfer.source;
        previous_to = transfer.destination;
        auto add = [&](CurrencyCollection& sum) {
          CurrencyCollection next;
          if (!CurrencyCollection::add(sum, value, next) || !next.tomis->unsigned_fits_bits(256)) return false;
          sum = std::move(next);
          return true;
        };
        if (transfer.source == account && !add(outgoing)) return false;
        if (transfer.destination == account && !add(incoming)) return false;
        auto next = participant_lt_detail::checked_add(index, 1);
        if (next.is_error()) return false;
        index = next.move_as_ok();
        return true;
      })) return td::Status::Error("invalid native allocation sequence or arithmetic");
  if (native.fees) {
    const auto& fees = *native.fees;
    TRY_RESULT(totals, checked_workchain_fee_totals(fees));
    if (updates.lookup_ref(fees.custody).is_null() || updates.lookup_ref(fees.coordinator).is_null()) {
      return td::Status::Error("fee allocation role absent from updates");
    }
    if (!totals.state.is_zero()) {
      if (index >= max_transfers) return td::Status::Error("fee allocation exceeds transfer budget");
      CurrencyCollection next;
      if (account == fees.custody) {
        if (!CurrencyCollection::add(outgoing, totals.state, next) || !next.tomis->unsigned_fits_bits(256)) {
          return td::Status::Error("fee allocation debit overflow");
        }
        outgoing = std::move(next);
      } else if (account == fees.coordinator) {
        if (!CurrencyCollection::add(incoming, totals.state, next) || !next.tomis->unsigned_fits_bits(256)) {
          return td::Status::Error("fee allocation credit overflow");
        }
        incoming = std::move(next);
      }
    }
  }
  CurrencyCollection available, result;
  if (!CurrencyCollection::add(credited, incoming, available) || !available.tomis->unsigned_fits_bits(256) ||
      !CurrencyCollection::sub(available, outgoing, result)) {
    return td::Status::Error("native allocation overflow or insufficient funds");
  }
  // Account wire amounts are narrower than the checked arithmetic workspace.
  vm::CellBuilder amount;
  if (!result.store(amount)) return td::Status::Error("allocated balance exceeds native wire encoding");
  return result;
}

}  // namespace block
