#pragma once

#include "block/transaction.h"
#include "block/native-bounce-body.h"
#include "block/native-bounce-storage.h"
#include "block/native-bounce-message.h"
#include "block/workchain-bounce-accounting.h"
#include "tol/extra-flags-constants.h"

namespace block {

enum class NativeDisposalBranch { UnexpectedCredit, Bounce };
enum class NativeDisposalSource { OriginalDestination, ProcessingAccount };
struct NativeDisposalProfile {
  NativeDisposalProfile(NativeDisposalSource source, NativeBounceDiagnostics diagnostics, bool allow_anycast)
      : source(source), diagnostics(std::move(diagnostics)), allow_anycast(allow_anycast) {}
  NativeDisposalSource source;
  NativeBounceDiagnostics diagnostics;
  bool allow_anycast;
};

struct WorkchainNativeDisposal {
  NativeDisposalBranch branch;
  td::Ref<vm::Cell> original; // Attribution survives either branch.
  td::Ref<vm::Cell> bounce;
  WorkchainAccountValueFlow row;
};

// Post-admission planning for an authenticated message already classified as
// misdirected. The caller supplies the authenticated final destination account
// and a processing account in that SAME workchain, plus allocated outgoing LT.
// The explicit source policy selects the anycast prefix. Its allow_anycast
// controls bounce routing, not cfg.disable_anycast's ordinary send policy.
// It must not pass user operations that belong to a legitimate Native entry.
// All closures must be fully materialized/validated, including opaque body refs.
// No queue removal, bucket counter update or Native record is published here.
// An Error/exception is NEVER permission to choose unexpected credit.
// A nonnull workchain table is required by reference, not inferred from cfg's
// optional pointer. Both arguments must belong to the same authenticated config.
inline td::Result<WorkchainNativeDisposal> plan_workchain_native_disposal(
    td::Ref<vm::Cell> message, tos::WorkchainId workchain, const td::Bits256& final_destination,
    const td::Bits256& processing_account, const CurrencyCollection& old_balance,
    td::uint64 outgoing_lt, td::uint32 now, ActionPhaseConfig cfg,
    const WorkchainSet& workchains, int extra_validation_cells, const NativeDisposalProfile& profile) {
  if (workchain < 0 || cfg.global_version < 12 || extra_validation_cells <= 0 ||
      (cfg.bounce_msg_body != 0 && cfg.bounce_msg_body != 256) ||
      cfg.fwd_std.first_frac > 65535 || cfg.fwd_mc.first_frac > 65535 ||
      (profile.source != NativeDisposalSource::OriginalDestination &&
       profile.source != NativeDisposalSource::ProcessingAccount)) {
    return td::Status::Error("invalid resolved disposal context");
  }
  cfg.workchains = &workchains;
  gen::Message::Record msg;
  gen::CommonMsgInfo::Record_int_msg_info info;
  CurrencyCollection imported;
  if (message.is_null() || !tlb::type_unpack_cell(message, gen::t_Message_Any, msg) ||
      !tlb::unpack_cell_inexact(message, info) || !info.ihr_disabled ||
      !imported.unpack(info.value) || !imported.validate_extra(extra_validation_cells) ||
      outgoing_lt <= info.created_lt) {
    return td::Status::Error("invalid admitted disposal message or logical time");
  }
  tos::WorkchainId destination_workchain;
  td::Bits256 destination_account;
  if (!tlb::t_MsgAddressInt.extract_std_address(info.dest, destination_workchain, destination_account) ||
      destination_workchain != workchain || destination_account != final_destination) {
    return td::Status::Error("disposal final destination differs from authenticated message");
  }
  auto flags = tlb::t_Tomis.as_integer(info.extra_flags);
  if (flags.is_null() || !flags->is_valid() ||
      td::cmp(flags & td::make_refint(tol::EXTRA_FLAGS_VALID_MASK), flags) != 0) {
    return td::Status::Error("invalid admitted disposal message flags");
  }
  auto credit = [&]() -> td::Result<WorkchainNativeDisposal> {
    CurrencyCollection after;
    if (!CurrencyCollection::add(old_balance, imported, after) ||
        !after.tomis->unsigned_fits_bits(256)) {
      return td::Status::Error("unexpected credit arithmetic overflow");
    }
    WorkchainAccountValueFlow row{processing_account, old_balance, imported, after,
                                  CurrencyCollection(0), CurrencyCollection(0)};
    TRY_STATUS(verify_workchain_value_flow({row}, {}, 1, 0, extra_validation_cells));
    return WorkchainNativeDisposal{NativeDisposalBranch::UnexpectedCredit, message, {}, std::move(row)};
  };
  if (info.bounced || !info.bounce) return credit();
  auto destination = info.src;
  bool to_mc = false;
  const auto& prefix = profile.source == NativeDisposalSource::OriginalDestination
      ? final_destination : processing_account;
  if (!transaction::rewrite_native_destination(destination, cfg, prefix, &to_mc, profile.allow_anycast)) return credit();

  vm::CellSlice original{*msg.body};
  if (original.fetch_ulong(1)) original = vm::load_cell_slice(original.fetch_ref());
  td::Ref<vm::CellSlice> original_body{true, original};
  vm::CellBuilder body;
  // Diagnostics and source policy require an explicit authenticated profile;
  // no production choice is installed by the ordinary-path comparison fixture.
  store_native_bounce_body(body, flags->get_bit(0), flags->get_bit(1), cfg.bounce_msg_body,
      original, original_body, info.value, info.created_lt, info.created_at, profile.diagnostics);
  TRY_RESULT(storage, measure_native_bounce_storage(!cfg.extra_currency_v2 || cfg.global_version < 13,
      info.value->prefetch_ref(), body.get_refs()));
  const auto& prices = cfg.fetch_msg_prices(to_mc);
  // Reuse the Native bigint formula, without truncating a large measured price.
  // uint64 prices and statistics bound the sum of two products below 2^129;
  // ceiling division by 2^16 plus the lump price fits 114 bits. The 120-bit
  // wire check is defensive, not a measured reachable resource boundary.
  auto total_fee = prices.compute_fwd_fees256(storage.cells, storage.bits);
  if (total_fee.is_null() || !total_fee->is_valid() || !total_fee->unsigned_fits_bits(120)) {
    return td::Status::Error("disposal price outside Native Tomis wire width");
  }
  if (imported.tomis < total_fee) return credit();
  auto collected_fee = prices.get_first_part(total_fee);
  TRY_RESULT(accounting, account_workchain_bounce(processing_account, old_balance, imported,
      total_fee, collected_fee, extra_validation_cells));
  CurrencyCollection remaining;
  if (!CurrencyCollection::sub(CurrencyCollection(total_fee), CurrencyCollection(collected_fee), remaining)) {
    return td::Status::Error("disposal forwarding split underflow");
  }
  // first_frac <= 65535 establishes collected <= total; checked subtraction
  // enforces 0 <= remaining <= total. Retain the full Tomis
  // width rather than truncate the Native bigint price to a machine integer.
  auto source = profile.source == NativeDisposalSource::OriginalDestination ? info.dest
      : tlb::t_MsgAddressInt.pack_std_address(workchain, processing_account);
  td::Ref<vm::Cell> output;
  if (!build_native_bounce_message(source, destination, accounting.returned,
      flags & td::make_refint(tol::EXTRA_FLAGS_VALID_MASK), remaining.tomis, outgoing_lt, now, body, output)) {
    return td::Status::Error("cannot construct admitted disposal bounce");
  }
  return WorkchainNativeDisposal{NativeDisposalBranch::Bounce, message, std::move(output), std::move(accounting.row)};
}

}  // namespace block
