#pragma once
#include <memory>
#include <set>

#include "crypto/block/mc-config.h"
#include "tos/tos-types.h"

#include "context.h"
#include "lifecycle.h"
#include "state.h"
namespace tos::auth {
// What a masterchain state admits on its own, before any registry is opened.
//
// Derivation decides in three stages: what the state says, what the registry
// says, and what the two say together. Only the first needs neither an anchor
// nor an archive read, so a caller holding a state and nothing else -- the
// manager, deciding whether to run a session -- can apply exactly these rules
// instead of keeping a smaller set of its own. A smaller set is the failure
// this exists to prevent: the manager would build a group whose roster
// derivation refuses, hand it to consensus, and each side would keep passing
// its own tests.
//
// Everything derivation goes on to use from the state is carried here, so the
// state is read once and the two stages cannot end up reading different things.
struct AdmittedState {
  std::unique_ptr<block::Config> config;
  std::shared_ptr<block::TotalValidatorSet> elected;
  td::Ref<vm::Cell> election_cell;
  // Every elected member's consensus key. Registry key selection refuses a key
  // that appears here, so the set is part of what the state admits rather than
  // something the next stage recomputes.
  std::set<Hash> consensus_keys;
  std::uint32_t gen_utime{};
  std::int32_t network{};
  std::uint32_t seqno{};
};
Result<AdmittedState> admit_masterchain_state(td::Ref<vm::Cell> masterchain_state);

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
