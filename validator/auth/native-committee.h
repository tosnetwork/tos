#pragma once
#include <set>

#include "tos/tos-types.h"

#include "context.h"
#include "lifecycle.h"
#include "state.h"
namespace tos::auth {
// The registry keys an identity authenticates with, and the one rule about them
// that two callers both have to apply: none of them may be a key any elected
// member uses for consensus.
//
// Conflating the two would let one key serve both roles, and derivation refuses
// a set where that happens. Binding has to refuse it as well, or an election
// produces a set that installs and then derives into nothing -- one member
// making every committee after it underivable. Both callers ask here so there
// is one answer rather than two that can drift.
Result<std::vector<Key>> committee_identity_keys(const Identity&, const KeyHistory&, std::uint32_t anchor,
                                                 const std::set<Hash>& consensus_keys);

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
