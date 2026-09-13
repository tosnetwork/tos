#include <algorithm>
#include <sodium.h>

#include "crypto.h"
namespace tos::auth {
namespace {
bool initialized() {
  static const bool ready = sodium_init() >= 0;
  return ready;
}
}  // namespace
Result<Hash> digest(std::string_view domain, std::span<const std::uint8_t> bytes) {
  if (!initialized())
    return Error{"backend-error"};
  if (domain.size() > 64 || bytes.size() > 67108864)
    return Error{"hash-bound"};
  std::string prefix = "TOS/P0/";
  prefix += domain;
  prefix += "/v1";
  prefix.push_back(0);
  crypto_hash_sha256_state state;
  Hash result;
  if (crypto_hash_sha256_init(&state) != 0 ||
      crypto_hash_sha256_update(&state, reinterpret_cast<const unsigned char*>(prefix.data()), prefix.size()) != 0 ||
      crypto_hash_sha256_update(&state, bytes.data(), bytes.size()) != 0 ||
      crypto_hash_sha256_final(&state, result.data()) != 0)
    return Error{"backend-error"};
  return result;
}
Result<AdmittedKey> AdmittedKey::admit(std::span<const std::uint8_t> bytes) {
  auto key = c0::AdmittedKey::admit({reinterpret_cast<const char*>(bytes.data()), bytes.size()});
  if (auto* error = std::get_if<c0::Error>(&key))
    return Error{*error == c0::Error::public_key ? "public-key" : "backend-error"};
  return AdmittedKey(std::get<c0::AdmittedKey>(std::move(key)));
}
Result<bool> AdmittedKey::verify(std::span<const std::uint8_t> message, std::span<const std::uint8_t> signature) const {
  auto result = key_.verify({reinterpret_cast<const char*>(message.data()), message.size()},
                            {reinterpret_cast<const char*>(signature.data()), signature.size()});
  if (std::holds_alternative<c0::Error>(result))
    return Error{"backend-error"};
  return std::get<bool>(result);
}
}  // namespace tos::auth
