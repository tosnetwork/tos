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
  Result<NativeRegistryBlock> apply_transaction(const Update&, const Authorizations&, const NativeIdentityContext&,
                                                ObjectReader&, StateReadBudget* work_remaining = nullptr) const;
  const NativeRegistry& state() const {
    return accepted_;
  }
};
}  // namespace tos::auth
