#pragma once
#include <optional>
#include <string_view>
#include <vector>

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
// The suites this build can verify. A key record declares which one it is, and
// the declaration is compared against the component that uses it, but nothing
// bound either declaration to the code that does the verifying: admission took
// the key bytes alone and assumed one algorithm. That held only because every
// caller also required the suite to be one. The suite now selects the verifier,
// so the record and the arithmetic cannot disagree.
//
// The registry still admits only suite 1: the frozen profile pins the policy's
// suite list, and every caller checks it. Suite 2 is reachable through this
// interface and through nothing on chain.
inline constexpr std::uint16_t suite_ed25519 = 1;
inline constexpr std::uint16_t suite_mldsa44 = 2;
inline constexpr std::uint16_t parameters_default = 1;

class AdmittedKey {
  std::uint16_t suite_{};
  std::optional<c0::AdmittedKey> ed25519_;
  std::vector<std::uint8_t> mldsa44_;
  AdmittedKey(std::uint16_t suite, c0::AdmittedKey key) : suite_(suite), ed25519_(std::move(key)) {
  }
  AdmittedKey(std::uint16_t suite, std::vector<std::uint8_t> key) : suite_(suite), mldsa44_(std::move(key)) {
  }

 public:
  // Refuses a suite this build cannot verify, and refuses key material that
  // does not belong to the suite it is offered under.
  static Result<AdmittedKey> admit(std::uint16_t suite, std::uint16_t parameters, std::span<const std::uint8_t> bytes);
  // Verifies with the backend that admitted the key, not with one chosen again
  // here. Choosing again is how the two could come apart.
  Result<bool> verify(std::span<const std::uint8_t> message, std::span<const std::uint8_t> signature) const;
  std::uint16_t suite() const {
    return suite_;
  }
};
}  // namespace tos::auth
