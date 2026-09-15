#pragma once
#include "state.h"
namespace tos::auth {
// Read only the authenticated entries needed by a snapshot. This view does not
// establish global registry validity or provide mutation/maximum-epoch authority.
class RegistryView final : public KeyHistory {
  td::Ref<vm::Cell> identities_root_, keys_root_, policies_root_;
  Hash chain_domain_{}, current_policy_{};
  Policy policy_;
  mutable StateReadBudget budget_;
  mutable std::map<Hash, Identity> identities_;
  mutable std::map<Hash, Key> keys_;
  Result<Bytes> read(td::Ref<vm::Cell>, const Hash&, std::size_t maximum) const;

 public:
  static Result<RegistryView> open(td::Ref<vm::Cell>, std::uint32_t coordinate, StateReadBudget = {});
  Result<Identity> identity(const Hash&) const;
  Result<Key> find(const Hash&) const override;
  Result<std::uint64_t> latest_epoch(const Hash&, KeySlot) const override;
  Result<bool> ever_registered(const Hash&) const override;
  const Hash& chain_domain() const {
    return chain_domain_;
  }
  const Hash& current_policy() const {
    return current_policy_;
  }
  const Policy& policy() const {
    return policy_;
  }
  StateReadBudget remaining() const {
    return budget_;
  }
};
}  // namespace tos::auth
