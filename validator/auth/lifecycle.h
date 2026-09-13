#pragma once
#include <optional>
#include <tuple>

#include "verify.h"
namespace tos::auth {
using KeySlot = std::tuple<std::uint8_t, std::uint16_t, std::uint16_t>;
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
Result<std::vector<Key>> select_identity_keys(const Identity&, const KeyHistory&, std::uint32_t anchor,
                                              const std::vector<KeySlot>& required);
}  // namespace tos::auth
