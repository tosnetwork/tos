#pragma once
#include <string_view>

#include "crypto/validator-auth/ed25519.h"

#include "types.h"
namespace tos::auth {
Result<Hash> digest(std::string_view domain, std::span<const std::uint8_t> bytes);
template <class T>
Result<Hash> object_id(std::string_view domain, const T& value) {
  auto raw = encode(value);
  if (!raw.ok())
    return raw.error();
  return digest(domain, raw.value());
}
class AdmittedKey {
  c0::AdmittedKey key_;
  explicit AdmittedKey(c0::AdmittedKey key) : key_(std::move(key)) {
  }

 public:
  static Result<AdmittedKey> admit(std::span<const std::uint8_t> bytes);
  Result<bool> verify(std::span<const std::uint8_t> message, std::span<const std::uint8_t> signature) const;
  const Hash& bytes() const {
    return key_.bytes();
  }
};
}  // namespace tos::auth
