#pragma once
#include "native-apply.h"
namespace tos::auth {
// Persistent native dictionaries retain the full public archive. Only bootstrap
// and checkpoint restoration enumerate it; successors share unchanged cell paths.
class NativeRegistry final : public CurrentRegistry {
  td::Ref<vm::Cell> identities_, keys_, policies_, control_, epochs_, due_, schedule_;
  Hash domain_{}, policy_{};
  std::uint64_t revision_ = 0;
  std::uint32_t coordinate_ = 0;
  mutable StateReadBudget budget_;
  NativeRegistry() = default;
  friend class NativeRegistryBlock;
  using Apply = std::function<Result<IdentityChange>(const NativeRegistry&, const Identity&, const Update&,
                                                     const Authorizations&)>;
  static void apply_updates(NativeRegistry&, const std::vector<std::pair<Update, Authorizations>>&, const Apply&);
  Result<NativeRegistry> apply(std::uint32_t, const std::vector<std::pair<Update, Authorizations>>&, const Apply&,
                               StateReadBudget) const;

 public:
  static Result<NativeRegistry> bootstrap(td::Ref<vm::Cell> registry, std::uint32_t, StateReadBudget = {});
  // Expected registry hash/coordinate come from the caller's authenticated native
  // context. Every redundant index is rebuilt and compared on external restore.
  static Result<NativeRegistry> restore(td::Ref<vm::Cell> checkpoint, const Hash& expected_registry,
                                        std::uint32_t expected_coordinate, StateReadBudget = {});
  Result<td::Ref<vm::Cell>> encode_cell() const;
  Result<td::Ref<vm::Cell>> checkpoint() const;
  Result<Identity> identity(const Hash&) const;
  Result<Key> find(const Hash&) const override;
  Result<std::uint64_t> latest_epoch(const Hash&, KeySlot) const override;
  Result<bool> ever_registered(const Hash&) const override;
  Result<NativeRegistry> apply_block(std::uint32_t, const std::vector<std::pair<Update, Authorizations>>&,
                                     const LifecycleAuthority&, StateReadBudget = {}) const;
  Result<NativeRegistry> apply_native_block(std::uint32_t, const std::vector<std::pair<Update, Authorizations>>&,
                                            const NativeIdentityContext&, ObjectReader&, StateReadBudget = {}) const;
  const Hash& chain_domain() const override {
    return domain_;
  }
  const Hash& current_policy() const override {
    return policy_;
  }
  std::uint32_t coordinate() const override {
    return coordinate_;
  }
  std::uint64_t revision() const {
    return revision_;
  }
  StateReadBudget remaining() const {
    return budget_;
  }
};
}  // namespace tos::auth
