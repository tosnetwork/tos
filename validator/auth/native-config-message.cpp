#include "vm/cellslice.h"
#include "vm/excno.hpp"

#include "native-config-message.h"
namespace tos::auth {

Result<NativeRegistryMessage> recognize_registry_message(td::Ref<vm::Cell> body) {
  if (body.is_null())
    return Error{"registry-message-absent"};
  try {
    vm::CellSlice cs{vm::NoVm{}, body};
    // The contract reads a 512-bit signature, then the action, then a seqno and
    // an expiry, before the two references. Anything shorter is not this
    // message, and reading past it would be reading whatever followed.
    //
    // The reference count is not checked here. A missing reference is caught
    // below, where fetching it yields nothing, and an extra one is caught by
    // the parse having to end exactly. A count check in front of both was
    // written first and turned out to be unreachable: no input trips it that
    // the other two do not already refuse, and a guard nothing can trip is
    // decoration that later reads as protection.
    if (!cs.have(512 + 32 + 32 + 32))
      return Error{"registry-message-shape"};
    cs.advance(512);
    if (cs.fetch_ulong(32) != native_registry_action)
      return Error{"registry-message-action"};
    cs.advance(32 + 32);
    auto update = cs.fetch_ref();
    auto evidence = cs.fetch_ref();
    if (update.is_null() || evidence.is_null())
      return Error{"registry-message-shape"};
    // A third reference is the configuration proposal a governance operation
    // finalizes. Whether one belongs here is not decided at this layer: the
    // host holds the decoded operation and refuses a proposal that does not
    // belong with it, or an operation that needs one and has none. Deciding it
    // twice would be two readings of the same update.
    td::Ref<vm::Cell> proposal;
    if (cs.size_refs() == 1)
      proposal = cs.fetch_ref();
    // The contract ends the parse here, so a body carrying more is not the
    // message it would accept.
    if (cs.size() != 0 || cs.size_refs() != 0)
      return Error{"registry-message-shape"};
    return NativeRegistryMessage{std::move(update), std::move(evidence), std::move(proposal)};
  } catch (const vm::VmError&) {
    return Error{"registry-message-shape"};
  }
}

Result<NativeElectionSetMessage> recognize_validator_set_message(td::Ref<vm::Cell> body) {
  if (body.is_null())
    return Error{"validator-set-message-absent"};
  try {
    vm::CellSlice cs{vm::NoVm{}, body};
    // The contract reads the action and a query id, then the set, then an
    // optional bindings reference, and ends the parse. Anything else is not
    // this message.
    if (!cs.have(32 + 64))
      return Error{"validator-set-message-shape"};
    if (cs.fetch_ulong(32) != native_validator_set_action)
      return Error{"validator-set-message-action"};
    cs.advance(64);
    auto elected = cs.fetch_ref();
    if (elected.is_null())
      return Error{"validator-set-message-shape"};
    td::Ref<vm::Cell> bindings;
    if (cs.size_refs() != 0)
      bindings = cs.fetch_ref();
    if (cs.size() != 0 || cs.size_refs() != 0)
      return Error{"validator-set-message-shape"};
    return NativeElectionSetMessage{std::move(elected), std::move(bindings)};
  } catch (const vm::VmError&) {
    return Error{"validator-set-message-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"validator-set-message-pruned"};
  }
}
}  // namespace tos::auth
