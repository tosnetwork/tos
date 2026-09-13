#include <algorithm>
#include <sodium.h>

#include "ed25519.h"
namespace tos::auth::c0 {
namespace {
constexpr Bytes32 identity{1};
constexpr Bytes32 order{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};
bool initialized() {
  static const bool ready = sodium_init() >= 0;
  return ready;
}
bool zero(const Bytes32& h) {
  return std::all_of(h.begin(), h.end(), [](auto b) { return b == 0; });
}
}  // namespace
std::variant<AdmittedKey, Error> AdmittedKey::admit(std::string_view input) {
  if (!initialized())
    return Error::backend;
  const auto* bytes = reinterpret_cast<const unsigned char*>(input.data());
  if (input.size() != 32 || crypto_core_ed25519_is_valid_point(bytes) != 1)
    return Error::public_key;
  Bytes32 key;
  std::copy_n(bytes, 32, key.begin());
  return AdmittedKey(key);
}
std::variant<bool, Error> AdmittedKey::verify(std::string_view message, std::string_view encoded_signature) const {
  if (encoded_signature.size() != 64)
    return false;
  const auto* signature = reinterpret_cast<const unsigned char*>(encoded_signature.data());
  Bytes32 r, s;
  std::copy_n(signature, 32, r.begin());
  std::copy_n(signature + 32, 32, s.begin());
  if (!std::lexicographical_compare(s.rbegin(), s.rend(), order.rbegin(), order.rend()))
    return false;
  // Round-trip the public R encoding without imposing a stronger R subgroup rule.
  Bytes32 canonical;
  if (crypto_core_ed25519_add(canonical.data(), r.data(), identity.data()) != 0 || canonical != r)
    return false;
  crypto_hash_sha512_state state;
  std::array<unsigned char, 64> wide;
  Bytes32 h;
  if (crypto_hash_sha512_init(&state) != 0 || crypto_hash_sha512_update(&state, r.data(), 32) != 0 ||
      crypto_hash_sha512_update(&state, bytes_.data(), 32) != 0 ||
      crypto_hash_sha512_update(&state, reinterpret_cast<const unsigned char*>(message.data()), message.size()) != 0 ||
      crypto_hash_sha512_final(&state, wide.data()) != 0)
    return Error::backend;
  crypto_core_ed25519_scalar_reduce(h.data(), wide.data());
  Bytes32 left = identity, ha = identity, right;
  if (!zero(s) && crypto_scalarmult_ed25519_base_noclamp(left.data(), s.data()) != 0)
    return Error::backend;
  if (!zero(h) && crypto_scalarmult_ed25519_noclamp(ha.data(), h.data(), bytes_.data()) != 0)
    return Error::backend;
  if (crypto_core_ed25519_add(right.data(), r.data(), ha.data()) != 0)
    return false;
  return sodium_memcmp(left.data(), right.data(), 32) == 0;
}
}  // namespace tos::auth::c0
