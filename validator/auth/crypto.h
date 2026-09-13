#pragma once
#include <string_view>

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
  Hash bytes_;
  explicit AdmittedKey(Hash bytes) : bytes_(bytes) {
  }

 public:
  static Result<AdmittedKey> admit(std::span<const std::uint8_t> bytes);
  Result<bool> verify(std::span<const std::uint8_t> message, std::span<const std::uint8_t> signature) const;
  const Hash& bytes() const {
    return bytes_;
  }
};
}  // namespace tos::auth
