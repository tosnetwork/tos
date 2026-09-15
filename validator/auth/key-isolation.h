#pragma once
#include <set>

#include "durable-log.h"
namespace tos::auth {
// Local Keyring deny set, not a source of chain or signing authority. Once a
// public key is designated, no API removes its designation, including retirement.
// Node startup must reconcile the provider's independently retained inventory
// before admitting P0 sessions; this file alone cannot detect whole-host rollback.
class KeyIsolation {
  std::string root_;
  std::unique_ptr<DurableLog> log_;
  int directory_fd_ = -1;
  bool exclusive_ = false;
  std::set<Hash> denied_;
  bool stopped_ = false;
  bool secure_parent() const;
  Result<bool> refresh();
  Result<bool> replay(std::span<const std::uint8_t>);

 public:
  explicit KeyIsolation(std::string root) : root_(std::move(root)) {
  }
  ~KeyIsolation();
  KeyIsolation(const KeyIsolation&) = delete;
  KeyIsolation& operator=(const KeyIsolation&) = delete;
  // Caller must stop new raw admissions and drain all its outstanding raw
  // operations before upgrading the directory lock here.
  Result<bool> protect(const Hash&);
  Result<bool> admit(const Hash&);
  Result<bool> admit_export_all();
};
}  // namespace tos::auth
