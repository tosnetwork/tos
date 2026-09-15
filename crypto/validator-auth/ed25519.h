#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string_view>
#include <variant>

struct evp_pkey_st;
namespace tos::auth::c0 {
using Bytes32 = std::array<std::uint8_t, 32>;
enum class Error { public_key, backend };
// Pure Ed25519 with the frozen C0 admission and noncofactored equation. This
// primitive has no policy, wire, VM or signer dependencies; callers bound and
// authorize the message before invoking it.
class AdmittedKey {
  Bytes32 bytes_;
  std::shared_ptr<evp_pkey_st> key_;
  explicit AdmittedKey(Bytes32 bytes, std::shared_ptr<evp_pkey_st> key) : bytes_(bytes), key_(std::move(key)) {
  }

 public:
  static std::variant<AdmittedKey, Error> admit(std::string_view bytes);
  std::variant<bool, Error> verify(std::string_view message, std::string_view signature) const;
  const Bytes32& bytes() const {
    return bytes_;
  }
};
}  // namespace tos::auth::c0
