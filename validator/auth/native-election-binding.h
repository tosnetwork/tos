#pragma once
#include <map>

#include "native-committee.h"
#include "registry-view.h"
namespace tos::auth {
// Attaching the registry binding to an elected validator set.
//
// Two facts have to meet and nothing holds both. The elector knows which
// account staked for which network key. The registry knows which identity an
// account owns. The join key is the staking account, so the link is asserted
// here, where the registry is already parsed by the one implementation that
// parses it.
//
// The identity a member names is a lookup key, not a claim to be trusted: what
// authenticates the link is that the registry says this identity is owned by
// the account that actually sent the stake, and the chain itself is what says
// which account sent it. Naming someone else's identity is refused, which
// matters because a stake id is public and would otherwise be consistent.
//
// Binding is all or nothing. A set with one member unbound is a set whose
// committee cannot be derived, and it would fail later, at derivation, where
// nothing can say which member was wrong or why.
struct ElectedBinding {
  Hash staking_account{};   // the masterchain account that sent the stake
  Hash claimed_identity{};  // the registry identity that account names

  bool operator==(const ElectedBinding&) const = default;
};

// Rewrites every descriptor of an elected set as an authenticated one, or
// refuses the set. Everything else the set carries -- validity window, counts,
// total weight, and each member's key, weight and address -- is preserved
// exactly; this adds a binding and changes nothing else.
//
// The anchor is the coordinate the set is being installed at. Which registry
// keys an identity authenticates with is a fact about a moment, and the rule
// that none of them may be a consensus key has to be applied against the same
// moment derivation will apply it against.
Result<td::Ref<vm::Cell>> bind_elected_validators(td::Ref<vm::Cell> elected,
                                                  const std::map<unsigned, ElectedBinding>& bindings,
                                                  const RegistryView&, std::uint32_t anchor);

// The bindings as a contract hands them over: a dictionary from the member's
// index in the elected set to the staking account and the identity it names.
// Decoded here, beside the only thing that consumes it, so the shape has one
// definition rather than one per caller.
Result<std::map<unsigned, ElectedBinding>> decode_elected_bindings(td::Ref<vm::Cell> bindings, unsigned total);
}  // namespace tos::auth
