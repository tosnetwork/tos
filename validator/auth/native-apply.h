#pragma once
#include "owner-proof.h"
#include "state.h"
namespace tos::auth {
// Implemented by independently authenticated native history. Looking up a peer's
// claimed coordinate never establishes finality or selects a competing fork.
class FinalizedAnchorSource {
 public:
  virtual ~FinalizedAnchorSource() = default;
  virtual Result<Anchor> finalized_anchor(std::uint32_t coordinate) const = 0;
};
struct NativeIdentityContext {
  ChainContext chain;
  const RegistrySnapshot& governing;
  const FinalizedAnchorSource& history;
};
// This authority is bound to one current per-operation view, including keys
// archived earlier in the same block. Reusing a parent view across updates is invalid.
class NativeLifecycleAuthority final : public LifecycleAuthority {
  const RegistryState& current_;
  const NativeIdentityContext& context_;
  ObjectReader& reader_;

 public:
  NativeLifecycleAuthority(const RegistryState& current, const NativeIdentityContext& context, ObjectReader& reader)
      : current_(current), context_(context), reader_(reader) {
  }
  Result<bool> validate_context() const;
  Result<bool> owner(const OwnerAuth&, const Update&, const Identity&) const override;
  Result<bool> possession(const PossessionAuth&, const Update&, const Key&) const override;
  Result<bool> administration(const IdentityAuth&, const Update&, const Identity&, std::uint32_t) const override;
};
// Replays exactly one complete ordered identity-update block. This composes
// native owner execution, PoP and current identity authority; native elector
// admission and native configuration contract application are separate boundaries.
Result<RegistryState> apply_native_identity_block(const RegistryState&, std::uint32_t,
                                                  const std::vector<std::pair<Update, Authorizations>>&,
                                                  const NativeIdentityContext&, ObjectReader&);
}  // namespace tos::auth
