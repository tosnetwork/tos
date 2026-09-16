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
  // The authenticated masterchain anchor the governing snapshot was derived
  // from. A policy operation stamps its activation with this, so the record and
  // the authority that admitted it name one fact rather than two.
  Anchor governing_anchor{};
};
// This authority is bound to one current per-operation view, including keys
// archived earlier in the same block. Reusing a parent view across updates is invalid.
class NativeLifecycleAuthority final : public LifecycleAuthority {
  const CurrentRegistry& current_;
  const NativeIdentityContext& context_;
  ObjectReader& reader_;
  // Who pays for the signature verifications this authority causes, when
  // anyone does. A replay that is not executing a transaction has nobody to
  // charge and passes nothing; what is admitted is the same either way.
  const SignatureMeter* meter_;

 public:
  NativeLifecycleAuthority(const CurrentRegistry& current, const NativeIdentityContext& context, ObjectReader& reader,
                           const SignatureMeter* meter = nullptr)
      : current_(current), context_(context), reader_(reader), meter_(meter) {
  }
  Result<bool> validate_context() const;
  Result<Anchor> governance(const Update&, const Authorizations&, const CurrentRegistry&,
                            std::uint32_t inclusion) const override;
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
