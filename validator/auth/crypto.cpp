#include <algorithm>
#include <sodium.h>

#include "pq/mldsa44.h"

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
Result<AdmittedKey> AdmittedKey::admit(std::uint16_t suite, std::uint16_t parameters,
                                       std::span<const std::uint8_t> bytes) {
  if (parameters != parameters_default)
    return Error{"unsupported-suite"};
  if (suite == suite_ed25519) {
    auto key = c0::AdmittedKey::admit({reinterpret_cast<const char*>(bytes.data()), bytes.size()});
    if (auto* error = std::get_if<c0::Error>(&key))
      return Error{*error == c0::Error::public_key ? "public-key" : "backend-error"};
    return AdmittedKey(suite, std::get<c0::AdmittedKey>(std::move(key)));
  }
  if (suite == suite_mldsa44) {
    // The only structural check the backend offers is the length; it has no
    // point validation to do. Material of the wrong length is refused for the
    // same reason a bad curve point is: it is not a key of this suite.
    if (bytes.size() != tos::pq::mldsa44_public_key_bytes)
      return Error{"public-key"};
    return AdmittedKey(suite, std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
  }
  return Error{"unsupported-suite"};
}
Result<bool> AdmittedKey::verify(std::span<const std::uint8_t> message, std::span<const std::uint8_t> signature) const {
  if (suite_ == suite_ed25519) {
    if (!ed25519_)
      return Error{"backend-error"};
    auto result = ed25519_->verify({reinterpret_cast<const char*>(message.data()), message.size()},
                                   {reinterpret_cast<const char*>(signature.data()), signature.size()});
    if (std::holds_alternative<c0::Error>(result))
      return Error{"backend-error"};
    return std::get<bool>(result);
  }
  if (suite_ == suite_mldsa44) {
    if (mldsa44_.size() != tos::pq::mldsa44_public_key_bytes)
      return Error{"backend-error"};
    if (message.size() > tos::pq::mldsa44_max_message_bytes)
      return Error{"message-bound"};
    auto result = tos::pq::verify_mldsa44({reinterpret_cast<const char*>(message.data()), message.size()}, {},
                                          {reinterpret_cast<const char*>(signature.data()), signature.size()},
                                          {reinterpret_cast<const char*>(mldsa44_.data()), mldsa44_.size()});
    switch (result) {
      case tos::pq::VerifyResult::valid:
        return true;
      case tos::pq::VerifyResult::invalid:
      case tos::pq::VerifyResult::malformed_input:
        return false;
      case tos::pq::VerifyResult::backend_error:
        break;
    }
    return Error{"backend-error"};
  }
  return Error{"unsupported-suite"};
}
}  // namespace tos::auth
