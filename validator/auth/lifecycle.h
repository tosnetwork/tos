#pragma once
#include <optional>
#include <tuple>

#include "verify.h"
namespace tos::auth {
using KeySlot = std::tuple<std::uint8_t, std::uint16_t, std::uint16_t>;
// Declared rather than included: the state that implements it includes this
// header, and a global operation only needs to name the current registry, not
// to know how it is built.
class CurrentRegistry;
class KeyHistory {
 public:
  virtual ~KeyHistory() = default;
  virtual Result<Key> find(const Hash&) const = 0;
  virtual Result<std::uint64_t> latest_epoch(const Hash& identity, KeySlot) const = 0;
  virtual Result<bool> ever_registered(const Hash& identity) const = 0;
};
class LifecycleAuthority {
 public:
  virtual ~LifecycleAuthority() = default;
  virtual Result<bool> owner(const OwnerAuth&, const Update&, const Identity&) const = 0;
  virtual Result<bool> possession(const PossessionAuth&, const Update&, const Key&) const = 0;
  virtual Result<bool> administration(const IdentityAuth&, const Update&, const Identity&,
                                      std::uint32_t inclusion) const = 0;
  // A global operation names no identity, so no identity's keys authorize it.
  // The governing committee's current-policy quorum does.
  //
  // The anchor the governing snapshot was derived from is returned rather than
  // read again by the caller. The activation a policy operation writes binds
  // that same anchor, so returning it here makes the record and the authority
  // one fact: a caller cannot stamp an activation with an anchor that did not
  // authorize it, because it never holds a second one.
  virtual Result<Anchor> governance(const Update&, const Authorizations&, const CurrentRegistry&,
                                    std::uint32_t inclusion) const = 0;
};
struct IdentityChange {
  Identity identity;
  std::optional<Key> archived_key;
};
Result<bool> validate_identity(const Identity&, const KeyHistory&);
Result<Identity> apply_due_transitions(const Identity&, const KeyHistory&, std::uint32_t parent_coordinate,
                                       std::uint32_t coordinate);
Result<IdentityChange> apply_identity_update(const Identity&, const KeyHistory&, const Update&, const Authorizations&,
                                             std::uint32_t inclusion, const LifecycleAuthority&);
// What a global operation produces. The registry has no identity to replace, so
// the effect is named rather than folded into an identity: a new policy, the
// activation that binds it, and the zero-identity record whose only content is
// the global admin nonce.
struct GlobalChange {
  Policy policy;
  Activation activation;
  Identity global;  // the zero-identity record, with its nonce advanced
};
// Apply one zero-identity operation.
//
// Operation 4 only. Operation 6 names a configuration parameter and a proposed
// cell by hash, and the frozen rules require the governing quorum *and* normal
// configuration voting for it; nothing yet carries an authorization across the
// rounds of that vote to the block that installs the result, so admitting one
// here would decide a rule rather than apply one.
Result<GlobalChange> apply_global_update(const Update&, const Authorizations&, const CurrentRegistry&,
                                         const Policy& current_policy, const Identity& global,
                                         const Activation* latest, std::uint32_t inclusion,
                                         const LifecycleAuthority&);
// Read-only staging admission: all lifecycle and owner/admin checks, with PoP
// absent. No successor state escapes before the final apply verifies actual PoP.
Result<bool> validate_stage_update(const Identity&, const KeyHistory&, const Update&, const Authorizations&,
                                   std::uint32_t inclusion, const LifecycleAuthority&);
Result<std::vector<Key>> select_identity_keys(const Identity&, const KeyHistory&, std::uint32_t anchor,
                                              const std::vector<KeySlot>& required);
}  // namespace tos::auth
