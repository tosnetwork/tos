#pragma once
#include "vm/validator-auth-host.h"

#include "native-transaction.h"
namespace tos::auth {
// The authority behind VAUTH_BIND for one elector transaction, and behind
// nothing else.
//
// The privileged surface is one interface with three operations, but no
// transaction legitimately performs all three. A registry update arrives as an
// external message carrying evidence and applies it; an elected set arrives as
// an internal message from the elector and is bound against the registry. They
// share no inputs: this host has no evidence, no object reader, no committee
// context and no owner history, because binding needs none of them.
//
// Giving each transaction only the operation its shape admits removes a whole
// class of question. A contract reached through the elector path cannot ask for
// an update to be applied, and one reached through the configuration path
// cannot ask for a set to be bound, so neither has to be argued about: the host
// it was given does not implement the other operation.
//
// Failure throws rather than returning a value the contract could mistake for
// success, for the same reason the update host does: the only outcome that
// leaves nothing half-applied is to abort the whole transaction.
class NativeElectionBindingHost final : public vm::ValidatorAuthHost {
  // The registry this block begins with, advanced to the coordinate being
  // built so a policy that is not yet effective cannot bind this set.
  NativeRegistryBlock accepted_;
  std::uint32_t coordinate_;
  // One meter for the binding reads of this transaction, so a second binding
  // starts where the first stopped rather than from a full allowance.
  StateReadBudget work_remaining_;
  std::uint64_t gas_per_entry_, gas_per_byte_;
  unsigned bindings_ = 0;

 public:
  NativeElectionBindingHost(NativeRegistryBlock accepted, std::uint32_t coordinate,
                            std::uint64_t gas_per_entry = 64, std::uint64_t gas_per_byte = 1)
      : accepted_(std::move(accepted))
      , coordinate_(coordinate)
      , work_remaining_(accepted_.state().remaining())
      , gas_per_entry_(gas_per_entry)
      , gas_per_byte_(gas_per_byte) {
  }

  td::Ref<vm::Cell> checkpoint(const Charge&) override;
  td::Ref<vm::Cell> apply(td::Ref<vm::Cell> update, td::Ref<vm::Cell> evidence, const Charge&) override;
  td::Ref<vm::Cell> bind(td::Ref<vm::Cell> elected, td::Ref<vm::Cell> bindings, const Charge&) override;

  // The candidate prefix this host binds against, for the same reason the
  // configuration host exposes one: what a transaction was opened onto is a
  // fact a test has to be able to read, or "it opened from the sequence" and
  // "it re-derived the parent's registry" look identical from outside.
  const NativeRegistryBlock& staged() const {
    return accepted_;
  }
  unsigned bindings() const {
    return bindings_;
  }
};
}  // namespace tos::auth
