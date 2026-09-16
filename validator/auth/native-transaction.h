#pragma once
#include "native-registry.h"
namespace tos::auth {
// An immutable accepted prefix of one block. Its parent revision is established
// only by begin(); failed transactions never replace the accepted prefix.
class NativeRegistryBlock {
  NativeRegistry accepted_;
  std::uint64_t parent_revision_;
  NativeRegistryBlock(NativeRegistry accepted, std::uint64_t revision)
      : accepted_(std::move(accepted)), parent_revision_(revision) {
  }

 public:
  static Result<NativeRegistryBlock> begin(const NativeRegistry&, std::uint32_t coordinate, StateReadBudget = {});
  // `work_remaining`, when given, receives what this transaction's reads left
  // of the allowance -- on refusal as well as on acceptance. The reads happen
  // either way, and a caller that could only learn about them on success would
  // let a refusal be free: arranging for the last step to fail would read the
  // registry for nothing. State rolls back on refusal; work does not.
  //
  // `meter`, when given, is told about each signature verification before it
  // happens. The reads this transaction makes are reported afterwards because
  // they are already bounded by the allowance; a verification is not bounded by
  // anything, so it is announced while the caller can still refuse.
  Result<NativeRegistryBlock> apply_transaction(const Update&, const Authorizations&, const NativeIdentityContext&,
                                                ObjectReader&, StateReadBudget* work_remaining = nullptr,
                                                const SignatureMeter* meter = nullptr) const;
  // Reduce the allowance without touching what the registry contains.
  //
  // A refused transaction leaves the prefix exactly where it was, but the reads
  // it made still happened. The copy that made them knows the remainder and is
  // then destroyed, so the number has to be handed back to the object that
  // outlives it or the next attempt begins from the same allowance again --
  // which is the whole of "state rolls back, work does not".
  //
  // It only ever reduces. A remainder larger than the current one is not a
  // settlement, it is a refill, and there is no legitimate source for one.
  Result<bool> settle_work(StateReadBudget remaining);

  const NativeRegistry& state() const {
    return accepted_;
  }
};
}  // namespace tos::auth
