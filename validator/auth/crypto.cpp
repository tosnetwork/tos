#include <algorithm>
#include <sodium.h>

#include "crypto.h"
namespace tos::auth {
namespace {
constexpr Hash identity{1};
constexpr Hash order{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                     0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};
bool initialized() {
  static const bool ready = sodium_init() >= 0;
  return ready;
}
bool zero(const Hash& h) {
  return std::all_of(h.begin(), h.end(), [](auto b) { return b == 0; });
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
  if (!initialized())
    return Error{"backend-error"};
  if (bytes.size() != 32 || crypto_core_ed25519_is_valid_point(bytes.data()) != 1)
    return Error{"public-key"};
  Hash key;
  std::copy(bytes.begin(), bytes.end(), key.begin());
  return AdmittedKey(key);
}
Result<bool> AdmittedKey::verify(std::span<const std::uint8_t> message, std::span<const std::uint8_t> signature) const {
  if (signature.size() != 64)
    return false;
  Hash r, s;
  std::copy_n(signature.begin(), 32, r.begin());
  std::copy_n(signature.begin() + 32, 32, s.begin());
  if (!std::lexicographical_compare(s.rbegin(), s.rend(), order.rbegin(), order.rend()))
    return false;
  // Round-trip the public R encoding without imposing a stronger R subgroup rule.
  Hash canonical;
  if (crypto_core_ed25519_add(canonical.data(), r.data(), identity.data()) != 0 || canonical != r)
    return false;
  crypto_hash_sha512_state state;
  std::array<unsigned char, 64> wide;
  Hash h;
  if (crypto_hash_sha512_init(&state) != 0 || crypto_hash_sha512_update(&state, r.data(), 32) != 0 ||
      crypto_hash_sha512_update(&state, bytes_.data(), 32) != 0 ||
      crypto_hash_sha512_update(&state, message.data(), message.size()) != 0 ||
      crypto_hash_sha512_final(&state, wide.data()) != 0)
    return Error{"backend-error"};
  crypto_core_ed25519_scalar_reduce(h.data(), wide.data());
  Hash left = identity, ha = identity, right;
  if (!zero(s) && crypto_scalarmult_ed25519_base_noclamp(left.data(), s.data()) != 0)
    return Error{"backend-error"};
  if (!zero(h) && crypto_scalarmult_ed25519_noclamp(ha.data(), h.data(), bytes_.data()) != 0)
    return Error{"backend-error"};
  if (crypto_core_ed25519_add(right.data(), r.data(), ha.data()) != 0)
    return false;
  return sodium_memcmp(left.data(), right.data(), 32) == 0;
}
}  // namespace tos::auth
