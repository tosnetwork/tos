#include <algorithm>
#include <openssl/evp.h>
#include <sodium.h>

#include "ed25519.h"
namespace tos::auth::c0 {
namespace {
constexpr Bytes32 order{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0x10};
bool initialized() {
  static const bool ready = sodium_init() >= 0;
  return ready;
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
  std::shared_ptr<EVP_PKEY> backend(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, bytes, 32), EVP_PKEY_free);
  if (!backend)
    return Error::backend;
  return AdmittedKey(key, std::move(backend));
}
std::variant<bool, Error> AdmittedKey::verify(std::string_view message, std::string_view encoded_signature) const {
  if (encoded_signature.size() != 64)
    return false;
  const auto* signature = reinterpret_cast<const unsigned char*>(encoded_signature.data());
  Bytes32 s;
  std::copy_n(signature + 32, 32, s.begin());
  if (!std::lexicographical_compare(s.rbegin(), s.rend(), order.rbegin(), order.rend()))
    return false;
  // Pure Ed25519 checks the canonical encoding of [S]B - [H(R,A,M)]A
  // against the supplied R. With the admitted prime-order A this is the exact
  // noncofactored C0 equation, including R=identity; no extra R rule is added.
  // The immutable key is shared across snapshots; each call owns its context.
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!context || EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key_.get()) != 1)
    return Error::backend;
  int result = EVP_DigestVerify(context.get(), signature, 64, reinterpret_cast<const unsigned char*>(message.data()),
                                message.size());
  if (result < 0)
    return Error::backend;
  return result == 1;
}
}  // namespace tos::auth::c0
