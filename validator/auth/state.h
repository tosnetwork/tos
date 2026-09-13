#pragma once
#include <set>

#include "cells.h"
#include "lifecycle.h"
namespace tos::auth {
// Resource admission is a local operational limit, not a committee or archive
// truncation rule. Exhaustion returns an error and never a partial state.
struct StateReadBudget {
  std::size_t entries = 1000000, bytes = 268435456;
};
class RegistryState final : public KeyHistory {
  Hash chain_domain_{}, current_policy_{};
  std::uint64_t revision_ = 0;
  std::uint32_t coordinate_ = 0;
  std::map<Hash, Identity> identities_;
  std::map<Hash, Key> keys_;
  std::map<Hash, Policy> policies_;
  std::map<std::uint32_t, Activation> activations_;
  std::map<Hash, Observation> observations_;
  std::map<std::pair<Hash, KeySlot>, std::uint64_t> epochs_;
  std::map<std::uint32_t, std::set<Hash>> due_;
  Result<bool> rebuild_indexes();
  Result<bool> validate();

 public:
  static Result<RegistryState> genesis(Hash chain_domain, const Policy&, std::vector<Identity>, std::vector<Key>);
  static Result<RegistryState> decode_cell(td::Ref<vm::Cell>, std::uint32_t coordinate, StateReadBudget = {});
  Result<td::Ref<vm::Cell>> encode_cell() const;
  Result<Key> find(const Hash&) const override;
  Result<std::uint64_t> latest_epoch(const Hash&, KeySlot) const override;
  Result<bool> ever_registered(const Hash&) const override;
  Result<Policy> policy_at(std::uint32_t anchor) const;
  // A rejected block returns no successor. Input state and all derived indexes
  // remain immutable. Due effects happen before updates in transaction order.
  Result<RegistryState> apply_block(std::uint32_t coordinate, const std::vector<std::pair<Update, Authorizations>>&,
                                    const LifecycleAuthority&) const;
  const std::map<Hash, Identity>& identities() const {
    return identities_;
  }
  const std::map<Hash, Key>& keys() const {
    return keys_;
  }
  const std::map<Hash, Policy>& policies() const {
    return policies_;
  }
  const Hash& chain_domain() const {
    return chain_domain_;
  }
  const Hash& current_policy() const {
    return current_policy_;
  }
  std::uint64_t revision() const {
    return revision_;
  }
  std::uint32_t coordinate() const {
    return coordinate_;
  }
};
}  // namespace tos::auth
