#include "vm/excno.hpp"

#include "native-transaction.h"
namespace tos::auth {
Result<NativeRegistryBlock> NativeRegistryBlock::begin(const NativeRegistry& parent, std::uint32_t at,
                                                       StateReadBudget budget) {
  auto next = parent.apply(
      at, {},
      [](const auto&, const auto&, const auto&, const auto&) -> Result<IdentityChange> {
        return Error{"empty-replay"};
      },
      budget);
  if (!next.ok())
    return next.error();
  return NativeRegistryBlock(std::move(next.value()), parent.revision());
}
Result<NativeRegistryBlock> NativeRegistryBlock::apply_transaction(const Update& update, const Authorizations& evidence,
                                                                   const NativeIdentityContext& context,
                                                                   ObjectReader& reader,
                                                                   StateReadBudget* work_remaining) const {
  // The copy the updates are applied to. It is declared outside the attempt so
  // what it read can be reported however the attempt ends.
  auto accepted = accepted_;
  auto settle = [&] {
    if (work_remaining)
      *work_remaining = accepted.remaining();
  };
  try {
    NativeRegistry::apply_updates(accepted, {{update, evidence}},
                                  [&](const NativeRegistry& view, const Identity& identity, const Update& operation,
                                      const Authorizations& authorizations) -> Result<IdentityChange> {
                                    NativeLifecycleAuthority authority(view, context, reader);
                                    auto valid = authority.validate_context();
                                    if (!valid.ok())
                                      return valid.error();
                                    return apply_identity_update(identity, view, operation, authorizations,
                                                                 view.coordinate(), authority);
                                  });
    if (parent_revision_ == UINT64_MAX) {
      settle();
      return Error{"registry-revision"};
    }
    accepted.revision_ = parent_revision_ + 1;
    settle();
    return NativeRegistryBlock(std::move(accepted), parent_revision_);
  } catch (const Error& e) {
    settle();
    return e;
  } catch (const vm::VmError&) {
    settle();
    return Error{"registry-cell"};
  } catch (const vm::VmVirtError&) {
    settle();
    return Error{"registry-pruned"};
  }
}
}  // namespace tos::auth
