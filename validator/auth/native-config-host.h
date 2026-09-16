#pragma once
#include "vm/validator-auth-host.h"

#include "native-transaction.h"
namespace tos::auth {
// The authority behind VAUTH_STATE and VAUTH_APPLY for one native configuration
// transaction. Native transaction execution constructs it; nothing else can,
// which is what keeps the registry unreachable from an ordinary contract.
//
// Effects are staged, not applied. The accepted prefix advances only when a
// transaction's update verifies, and the caller reads the staged result after
// the transaction commits. A failed update leaves the prefix exactly where the
// previous accepted transaction left it, so a reverted transaction cannot move
// the registry.
//
// Failure throws rather than returning a value the contract could mistake for
// success. The contract asked for an update to be applied; if it cannot be,
// the only outcome that leaves nothing half-applied is to abort the whole
// transaction.
class NativeConfigHost final : public vm::ValidatorAuthHost {
  NativeRegistryBlock accepted_;
  const NativeIdentityContext& context_;
  ObjectReader& reader_;
  // The evidence this transaction was admitted with, and what it said. The
  // instruction receives the same reference the contract was given, so the host
  // recognises it instead of reading it again: one admitted source for what the
  // transaction carried, rather than two readings of one cell that can disagree
  // about its shape.
  td::Ref<vm::Cell> admitted_evidence_;
  Authorizations admitted_;
  // The block being built. A registry policy that is not yet effective at this
  // coordinate must not bind a set this block installs.
  std::uint32_t coordinate_;
  // One meter for the binding reads of this transaction. Opening a view with a
  // copy of the state's budget and never taking the remainder back charged
  // nothing at all, and started every binding from a full allowance again.
  //
  // It is not yet the whole invariant: applying an update still draws on the
  // budget carried inside the registry state, so binding reads do not limit a
  // later apply. Closing that needs the budget threaded through
  // apply_transaction, which this does not do.
  StateReadBudget work_remaining_;
  std::uint64_t gas_per_entry_, gas_per_byte_;
  unsigned checkpoints_ = 0, updates_ = 0, bindings_ = 0;

 public:
  // Charging is derived from the work the registry itself reports, so the price
  // of a transaction is a function of what it actually read rather than of a
  // constant that would drift from it.
  NativeConfigHost(NativeRegistryBlock accepted, const NativeIdentityContext& context, ObjectReader& reader,
                   std::uint32_t coordinate, td::Ref<vm::Cell> admitted_evidence, Authorizations admitted,
                   std::uint64_t gas_per_entry = 64, std::uint64_t gas_per_byte = 1)
      : accepted_(std::move(accepted))
      , context_(context)
      , reader_(reader)
      , admitted_evidence_(std::move(admitted_evidence))
      , admitted_(std::move(admitted))
      , coordinate_(coordinate)
      , work_remaining_(accepted_.state().remaining())
      , gas_per_entry_(gas_per_entry)
      , gas_per_byte_(gas_per_byte) {
  }

  td::Ref<vm::Cell> checkpoint(const Charge&) override;
  td::Ref<vm::Cell> apply(td::Ref<vm::Cell> update, td::Ref<vm::Cell> evidence, const Charge&) override;
  td::Ref<vm::Cell> bind(td::Ref<vm::Cell> elected, td::Ref<vm::Cell> bindings, const Charge&) override;

  // The staged prefix after execution. Native commit installs this and nothing
  // else; there is no path that installs a registry the host did not accept.
  const NativeRegistryBlock& staged() const {
    return accepted_;
  }
  unsigned checkpoints() const {
    return checkpoints_;
  }
  unsigned updates() const {
    return updates_;
  }
  unsigned bindings() const {
    return bindings_;
  }
};
}  // namespace tos::auth
