#pragma once

#include "block/block.h"
#include "block/block-parse.h"

namespace block {

// Serialize an already authorized/priced bounce. Addresses are already
// rewritten and the LT is already allocated. This performs no account debit,
// branch selection or queue publication. A failed construction is not nofunds.
// Body may be consumed when encoded by reference. Builder/allocation exceptions
// retain their original types for the caller's source-aware boundary.
inline bool build_native_bounce_message(
    const td::Ref<vm::CellSlice>& source, const td::Ref<vm::CellSlice>& destination,
    const CurrencyCollection& returned, const td::RefInt256& extra_flags,
    td::uint64 remaining_forwarding_fee, td::uint64 created_lt, td::uint32 created_at,
    vm::CellBuilder& body, td::Ref<vm::Cell>& output) {
  vm::CellBuilder cb;
  if (!(cb.store_long_bool(5, 4)                         // int_msg_info$0: IHR disabled, bounced
        && cb.append_cellslice_bool(source)             // src:MsgAddressInt
        && cb.append_cellslice_bool(destination)        // dest:MsgAddressInt
        && returned.store(cb)                          // value:CurrencyCollection
        && tlb::t_Tomis.store_integer_ref(cb, extra_flags) // extra_flags:(VarUInteger 16)
        && tlb::t_Tomis.store_long(cb, remaining_forwarding_fee) // fwd_fee:Tomis
        && cb.store_long_bool(created_lt, 64)           // created_lt:uint64
        && cb.store_long_bool(created_at, 32)           // created_at:uint32
        && cb.store_bool_bool(false))) {               // init:(Maybe ...) = none
    return false;
  }
  // A CellBuilder has at most 1023 bits; adding the Either selector cannot
  // overflow int. This is encoding capacity, not monetary/resource admission.
  if (cb.can_extend_by(1 + body.size(), body.size_refs())) {
    if (!(cb.store_bool_bool(false) && cb.append_builder_bool(body))) return false;
  } else {
    if (!(cb.store_bool_bool(true) && cb.store_builder_ref_bool(std::move(body)))) return false;
  }
  return cb.finalize_to(output);
}

}  // namespace block
