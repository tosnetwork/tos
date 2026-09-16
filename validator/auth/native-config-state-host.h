#pragma once
#include <memory>

#include "vm/validator-auth-host.h"

#include "native-config-sequence.h"
namespace tos::auth {
// The authority behind VAUTH_STATE for one tick-tock transaction of the
// configuration account, and behind nothing else.
//
// A block with no registry message still has native state to persist. The
// prefix every transaction opens from already carries the transitions that fall
// due at this coordinate, and if nothing writes it back the account keeps the
// parent's parameter 46 -- whose schedule still names a transition as due at a
// coordinate that has passed. The next block's registry then refuses to open at
// all, and the chain stops making masterchain blocks.
//
// It is persisted the way everything else is: the contract asks for the state,
// the contract writes it, the ordinary transaction commits. A native path that
// wrote the account directly would be a second installer beside the contract,
// which is the arrangement this whole design exists to remove.
//
// Applying and binding are refused as the absent host refuses them. A tick-tock
// carries no message, no evidence and no elected set; a contract that asks for
// either through this path is asking for an instruction that does not exist for
// this caller.
class NativeConfigStateHost final : public vm::ValidatorAuthHost {
  NativeRegistryBlock accepted_;
  std::uint64_t gas_per_entry_, gas_per_byte_;
  unsigned checkpoints_ = 0;

 public:
  NativeConfigStateHost(NativeRegistryBlock accepted, std::uint64_t gas_per_entry = 64,
                        std::uint64_t gas_per_byte = 1)
      : accepted_(std::move(accepted)), gas_per_entry_(gas_per_entry), gas_per_byte_(gas_per_byte) {
  }

  td::Ref<vm::Cell> checkpoint(const Charge&) override;
  td::Ref<vm::Cell> apply(td::Ref<vm::Cell> update, td::Ref<vm::Cell> evidence, const Charge&) override;
  td::Ref<vm::Cell> bind(td::Ref<vm::Cell> elected, td::Ref<vm::Cell> bindings, const Charge&) override;

  // The candidate this tick-tock offers. It installs nothing; the sequence
  // promotes it only if the account's commit binds to it exactly.
  const NativeRegistryBlock& staged() const {
    return accepted_;
  }
  unsigned checkpoints() const {
    return checkpoints_;
  }
};

// Owns the host a tick-tock borrows, for the same reason the other transactions
// do: the host holds the registry block it reads from.
class NativeConfigStateTransaction {
  NativeConfigStateHost host_;
  explicit NativeConfigStateTransaction(NativeRegistryBlock accepted) : host_(std::move(accepted)) {
  }

 public:
  // Refuses unless this is the configuration account.
  //
  // The check is here because there is nothing else to make it. A tick-tock has
  // no message, and the compute-phase predicate delegates the account question
  // to the message assembler -- which refuses anything not addressed to the
  // configuration account. With no message there is no assembler, and the
  // special accounts a tick-tock runs for include the elector.
  static Result<std::unique_ptr<NativeConfigStateTransaction>> open(const NativeConfigSequence&, const Hash& account);

  vm::ValidatorAuthHost& host() {
    return host_;
  }
  const NativeConfigStateHost& host_state() const {
    return host_;
  }
};
}  // namespace tos::auth
