#pragma once
#include "tos/tos-types.h"

#include "context.h"
#include "state.h"
namespace tos::auth {
// The caller supplies an independently validated masterchain anchor. Derivation
// uses its actual config and election state, never peer-supplied member weights.
class NativeCommittee {
  RegistrySnapshot snapshot_;
  std::vector<tos::ValidatorDescr> transport_order_;
  Anchor anchor_;
  NativeCommittee(RegistrySnapshot snapshot, std::vector<tos::ValidatorDescr> transport, Anchor anchor)
      : snapshot_(std::move(snapshot)), transport_order_(std::move(transport)), anchor_(anchor) {
  }

 public:
  static Result<NativeCommittee> derive(td::Ref<vm::Cell> masterchain_state, const Anchor& trusted_anchor,
                                        const ChainContext&, tos::ShardIdFull, std::uint32_t catchain,
                                        StateReadBudget = {});
  const RegistrySnapshot& snapshot() const {
    return snapshot_;
  }
  const std::vector<tos::ValidatorDescr>& transport_order() const {
    return transport_order_;
  }
  const Anchor& anchor() const {
    return anchor_;
  }
};
}  // namespace tos::auth
