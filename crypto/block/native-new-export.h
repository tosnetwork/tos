#pragma once

#include "block/block-parse.h"

namespace block {

struct NativeNewExport {
  td::Ref<vm::Cell> envelope, descriptor, enqueued;
};

// Shared Native wire construction, not routing, source authorization, queue
// admission or deferral policy. The caller supplies the already resolved
// envelope and transaction. No dictionary is mutated here; allocation/Cell
// exceptions retain their original category and provenance.
inline td::Result<NativeNewExport> encode_native_new_export(
    const tlb::MsgEnvelope::Record_std& envelope, td::Ref<vm::Cell> transaction,
    tos::LogicalTime enqueued_lt, bool deferred) {
  if (transaction.is_null()) return td::Status::Error("missing Native export transaction");
  NativeNewExport result;
  if (!tlb::pack_cell(result.envelope, envelope)) {
    return td::Status::Error("cannot encode Native export envelope");
  }
  vm::CellBuilder descriptor, enqueued;
  // Fresh builders hold only 5 bits/two refs and 64 bits/one ref respectively;
  // the references are non-null. Capacity is structural, not a fallible input
  // policy. Preserve the complete uint64 LT bit pattern, as Native does.
  descriptor.store_long(deferred ? 0b10100 : 0b001, deferred ? 5 : 3)
      .store_ref(result.envelope).store_ref(transaction);
  enqueued.store_long(enqueued_lt, 64).store_ref(result.envelope);
  result.descriptor = descriptor.finalize();
  result.enqueued = enqueued.finalize();
  return result;
}

}  // namespace block
