#pragma once

#include "block/transaction.h"
#include "block/block-parse.h"
#include "block/workchain-confidential-state.h"

namespace block {

// No narrowing of the historical uint64 amount through a signed constructor.
inline CurrencyCollection workchain_refund_value(std::uint64_t amount) {
  auto cell = vm::CellBuilder().store_long(amount, 64).finalize();
  return CurrencyCollection(vm::load_cell_slice(cell).fetch_int256(64, false));
}

// Authenticated destination policy, shared with Native sends. This establishes
// format/workchain acceptance, NOT existence or eventual delivery. Acquisition
// and allocation exceptions retain their provenance at the enclosing boundary.
inline td::Status validate_workchain_refund_destination(
    const WorkchainRegistrationFunding& funding, const WorkchainSet& workchains) {
  if (funding.refund_workchain < -128 || funding.refund_workchain > 127)
    return td::Status::Error(-7200, "refund destination is not a standard Native address");
  auto destination = tlb::t_MsgAddressInt.pack_std_address(funding.refund_workchain, funding.refund_account);
  ActionPhaseConfig cfg;
  cfg.workchains = &workchains;
  if (destination.is_null() || !transaction::rewrite_native_destination(
          destination, cfg, td::Bits256::zero(), nullptr, false))
    return td::Status::Error(-7200, "refund destination workchain does not accept messages");
  return td::Status::OK();
}

// Read-only checks over locally rebuilt Native artifacts. NOT closure
// authorization: DLEQ and authenticated lifecycle/pending checks precede this.
// A caller comparing candidate artifacts classifies a mismatch as candidate
// invalid; construction callers classify their own mismatch as local failure.
inline td::Status verify_workchain_refund_message(
    const WorkchainRegistrationFunding& historical, std::uint64_t bucket_before,
    std::uint64_t bucket_after, const CurrencyCollection& balance_before,
    const CurrencyCollection& balance_after, const CurrencyCollection& collected_fees,
    tos::WorkchainId source_workchain, const td::Bits256& source_account,
    const std::vector<td::Ref<vm::Cell>>& messages) {
  // Checked before subtraction: a dedicated bucket cannot increase here or
  // fund forwarding fees. Its sole debit must be the historical payment.
  if (bucket_after > bucket_before || bucket_before - bucket_after != historical.paid_deposit)
    return td::Status::Error("refund bucket debit differs from historical payment");
  if (messages.size() != 1 || messages[0].is_null())
    return td::Status::Error("refund requires exactly one outbound message");
  gen::Message::Record msg;
  gen::CommonMsgInfo::Record_int_msg_info info;
  CurrencyCollection value;
  tos::WorkchainId src_wc, dst_wc;
  td::Bits256 src, dst;
  if (!tlb::type_unpack_cell(messages[0], gen::t_Message_Any, msg) ||
      !gen::csr_unpack(msg.info, info) || !info.ihr_disabled || !info.bounce || info.bounced ||
      !tlb::t_MsgAddressInt.extract_std_address(info.src, src_wc, src) ||
      !tlb::t_MsgAddressInt.extract_std_address(info.dest, dst_wc, dst) ||
      src_wc != source_workchain || src != source_account ||
      dst_wc != historical.refund_workchain || dst != historical.refund_account || !value.unpack(info.value))
    return td::Status::Error("refund message destination or profile mismatch");
  if (value != workchain_refund_value(historical.paid_deposit))
    return td::Status::Error("refund message value differs from historical payment");
  auto forward = tlb::t_Tomis.as_integer(info.fwd_fee);
  if (forward.is_null() || !forward->is_valid() || !forward->unsigned_fits_bits(120))
    return td::Status::Error("refund forwarding remainder malformed");
  CurrencyCollection unlocked_before, unlocked_after, fees, expected;
  // Section 3.1 assigns the coordinator's nonlocked Native funds to operations;
  // private principal belongs to custody, not this account. Both checked
  // subtractions require Native balance to cover the locked bucket.
  // Therefore no part of any other account's deposit can finance this send.
  if (!CurrencyCollection::sub(balance_before, workchain_refund_value(bucket_before), unlocked_before) ||
      !CurrencyCollection::sub(balance_after, workchain_refund_value(bucket_after), unlocked_after))
    return td::Status::Error("refund fees invade the locked bucket");
  if (!CurrencyCollection::add(collected_fees, CurrencyCollection(forward), fees) ||
      !CurrencyCollection::add(unlocked_after, fees, expected) || expected != unlocked_before)
    return td::Status::Error("refund fees do not reconcile to the operating budget");
  return td::Status::OK();
}
}  // namespace block
