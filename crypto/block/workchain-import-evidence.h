#pragma once

#include <map>
#include <vector>

#include "block/transaction.h"
#include "block/block-parse.h"

namespace block {

struct WorkchainFinalImportEvidence {
  td::Ref<vm::Cell> in_msg_descr;
  std::map<td::Bits256, CurrencyCollection> account_credits;
  CurrencyCollection value_imported{0}, fees_collected{0};
};

namespace final_import_detail {

// Materialize final imports referencing already serialized Native transactions.
// This does not authenticate queue membership/completeness, transaction roles,
// or disposal policy. Those are host obligations, including own-queue dequeue
// evidence and DispatchQueue handling. Only standard final imports are built.
// All supplied closures require prior source-aware admission; entry bounds
// alone do not bound cell or currency traversal. Exceptions keep their source.
template <class ResolveAccount>
td::Result<WorkchainFinalImportEvidence> build(
    tos::WorkchainId workchain, int global_version,
    const std::vector<td::Ref<vm::Cell>>& envelopes,
    const std::map<td::Bits256, td::Ref<vm::Cell>>& transactions,
    std::uint64_t max_inbound, std::uint64_t max_transactions, int extra_validation_cells,
    const ResolveAccount& resolve_account) {
  if (workchain < 0 || global_version < transaction::Transaction::kStorageParticipantMinGlobalVersion ||
      envelopes.size() > max_inbound || transactions.size() > max_transactions || extra_validation_cells <= 0) {
    return td::Status::Error("invalid final import context or limits");
  }
  tlb::Aug_InMsgDescr augmentation(global_version);
  vm::AugmentedDictionary imports(256, augmentation);
  WorkchainFinalImportEvidence result;
  auto add = [](CurrencyCollection& sum, const CurrencyCollection& value) {
    CurrencyCollection next;
    if (!CurrencyCollection::add(sum, value, next) || !next.tomis->unsigned_fits_bits(256)) return false;
    sum = std::move(next);
    return true;
  };
  for (const auto& root : envelopes) {
    tlb::MsgEnvelope::Record_std envelope;
    gen::CommonMsgInfo::Record_int_msg_info info;
    gen::MsgAddressInt::Record_addr_std destination;
    CurrencyCollection value;
    if (!tlb::unpack_cell(root, envelope) || !tlb::unpack_cell_inexact(envelope.msg, info) ||
        !gen::csr_unpack(info.dest, destination) || destination.anycast->size() != 1 ||
        destination.workchain_id != workchain || !info.ihr_disabled || !value.unpack(info.value) ||
        !value.tomis->unsigned_fits_bits(256) || !value.validate_extra(extra_validation_cells) ||
        envelope.fwd_fee_remaining.is_null() || !envelope.fwd_fee_remaining->unsigned_fits_bits(256)) {
      return td::Status::Error("invalid final import envelope or value");
    }
    auto original_fee = tlb::t_Tomis.as_integer(info.fwd_fee);
    if (original_fee.is_null() || envelope.fwd_fee_remaining > original_fee) {
      return td::Status::Error("remaining import fee exceeds original forwarding fee");
    }
    const td::Bits256 processing_account = resolve_account(destination.address);
    auto found = transactions.find(processing_account);
    gen::Transaction::Record transaction;
    if (found == transactions.end() || !tlb::unpack_cell(found->second, transaction) ||
        transaction.account_addr != processing_account || info.created_lt >= transaction.lt ||
        (envelope.emitted_lt && envelope.emitted_lt.value() >= transaction.lt)) {
      return td::Status::Error("final import transaction or logical time mismatch");
    }
    vm::CellBuilder record;
    record.store_long(4, 3).store_ref(root).store_ref(found->second);
    if (!tlb::t_Tomis.store_integer_ref(record, envelope.fwd_fee_remaining)) {
      return td::Status::Error("cannot encode final import forwarding fee");
    }
    auto in_msg = record.finalize();
    vm::CellBuilder fees_cell;
    auto in_slice = vm::load_cell_slice(in_msg);
    if (!tlb::t_InMsg.get_import_fees(fees_cell, in_slice, global_version)) {
      return td::Status::Error("cannot reconstruct Native final import fees");
    }
    gen::ImportFees::Record decoded;
    CurrencyCollection imported;
    if (!tlb::unpack_cell(fees_cell.finalize(), decoded) || !imported.unpack(decoded.value_imported)) {
      return td::Status::Error("invalid Native final import augmentation");
    }
    auto fee = tlb::t_Tomis.as_integer(decoded.fees_collected);
    if (fee.is_null() || !fee->unsigned_fits_bits(256)) return td::Status::Error("invalid Native import fee amount");
    CurrencyCollection collected(fee), credited;
    // Sub checks each currency and nonnegativity. Fees are imported at the
    // block level but collected there, never credited to an engine account.
    if (!CurrencyCollection::sub(imported, collected, credited) || credited != value ||
        collected != CurrencyCollection(envelope.fwd_fee_remaining)) {
      return td::Status::Error("Native final import credit or fee mismatch");
    }
    auto& credit = result.account_credits.try_emplace(processing_account, CurrencyCollection(0)).first->second;
    if (!add(credit, credited) || !add(result.value_imported, imported) || !add(result.fees_collected, collected)) {
      return td::Status::Error("final import accumulation overflow");
    }
    if (!imports.set(envelope.msg->get_hash().bits(), 256, vm::load_cell_slice(in_msg),
                     vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("duplicate or unencodable final import");
    }
  }
  // Verify the complete Native dictionary augmentation, not only per-record
  // arithmetic. A successful return contains an actual InMsgDescr root.
  gen::ImportFees::Record aggregate;
  CurrencyCollection imported;
  if (!tlb::csr_unpack(imports.get_root_extra(), aggregate) || !imported.unpack(aggregate.value_imported)) {
    return td::Status::Error("invalid final import dictionary augmentation");
  }
  auto fees = tlb::t_Tomis.as_integer(aggregate.fees_collected);
  if (fees.is_null() || imported != result.value_imported || CurrencyCollection(fees) != result.fees_collected) {
    return td::Status::Error("final import dictionary totals mismatch");
  }
  result.in_msg_descr = imports.get_wrapped_dict_root();
  return result;
}

}  // namespace final_import_detail

// The strict path preserves Native destination == transaction account.
inline td::Result<WorkchainFinalImportEvidence> build_workchain_final_imports(
    tos::WorkchainId workchain, int global_version,
    const std::vector<td::Ref<vm::Cell>>& envelopes,
    const std::map<td::Bits256, td::Ref<vm::Cell>>& transactions,
    std::uint64_t max_inbound, std::uint64_t max_transactions, int extra_validation_cells) {
  return final_import_detail::build(workchain, global_version, envelopes, transactions, max_inbound,
                                    max_transactions, extra_validation_cells,
                                    [](const td::Bits256& destination) { return destination; });
}

// Explicit V2 record shape, not activation of a Native validation exception.
// Authenticated role/profile resolution and full transaction reconstruction
// belong to the enclosing host. The original message/envelope is never rewritten.
// A foreign destination is processed by the coordinator; legitimate entry
// addresses retain their own processing account. Credits are gross imported
// value, not disposal outcomes or custody backing. Business admission, bucket
// accounting and any matching bounce OutMsg remain separate host obligations.
inline td::Result<WorkchainFinalImportEvidence> build_workchain_routed_final_imports(
    tos::WorkchainId workchain, int global_version,
    const std::vector<td::Ref<vm::Cell>>& envelopes,
    const std::map<td::Bits256, td::Ref<vm::Cell>>& transactions,
    const td::Bits256& coordinator, const td::Bits256& custody,
    std::uint64_t max_inbound, std::uint64_t max_transactions, int extra_validation_cells) {
  if (coordinator == custody) return td::Status::Error("final import roles must be distinct");
  return final_import_detail::build(workchain, global_version, envelopes, transactions, max_inbound,
                                    max_transactions, extra_validation_cells,
                                    [&](const td::Bits256& destination) {
                                      return destination == custody ? custody : coordinator;
                                    });
}

}  // namespace block
