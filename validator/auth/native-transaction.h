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
  Result<NativeRegistryBlock> apply_transaction(const Update&, const Authorizations&, const NativeIdentityContext&,
                                                ObjectReader&) const;
  const NativeRegistry& state() const {
    return accepted_;
  }
};
}  // namespace tos::auth
