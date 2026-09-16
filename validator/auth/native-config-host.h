#pragma once
#include "vm/validator-auth-host.h"

#include "native-transaction.h"
namespace tos::auth {
// The authority behind VAUTH_STATE and VAUTH_APPLY for one native configuration
// transaction, and behind neither anything else nor VAUTH_BIND. Native
// transaction execution constructs it; nothing else can, which is what keeps
// the registry unreachable from an ordinary contract.
//
// Binding an elected set is a different transaction with different inputs and
// has its own host. Sharing one would mean a single object constructed from two
// unrelated message shapes, and the operation a contract could reach would
// depend on which of them happened to build it.
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
  std::uint64_t gas_per_entry_, gas_per_byte_;
  unsigned checkpoints_ = 0, updates_ = 0;

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
      , gas_per_entry_(gas_per_entry)
      , gas_per_byte_(gas_per_byte) {
  }

  td::Ref<vm::Cell> checkpoint(const Charge&) override;
  td::Ref<vm::Cell> apply(td::Ref<vm::Cell> update, td::Ref<vm::Cell> evidence, const Charge&) override;
  td::Ref<vm::Cell> bind(td::Ref<vm::Cell> elected, td::Ref<vm::Cell> bindings, const Charge&) override;

  // The candidate native prefix this transaction produced.
  //
  // It never installs account or global state. The configuration contract alone
  // produces persistent c4; the enclosing sequence may promote this candidate
  // only after that account actually commits and the committed c4 binds exactly
  // to it. Reading this as "what will be installed" is what would make the host
  // a second installation path beside the contract, and the two would then be
  // two descriptions of one fact with nothing comparing them.
  const NativeRegistryBlock& staged() const {
    return accepted_;
  }
  unsigned checkpoints() const {
    return checkpoints_;
  }
  unsigned updates() const {
    return updates_;
  }
};
}  // namespace tos::auth
