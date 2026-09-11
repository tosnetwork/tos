/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "mldsa44.h"
#include <cstdint>
#include "mldsa_native.h"

namespace tos::pq {
static_assert(MLDSA44_PUBLICKEYBYTES == mldsa44_public_key_bytes);
static_assert(MLDSA44_BYTES == mldsa44_signature_bytes);

VerifyResult verify_mldsa44(std::string_view message, std::string_view context,
                          std::string_view signature, std::string_view public_key) noexcept {
  if (message.size() > mldsa44_max_message_bytes || context.size() > mldsa44_max_context_bytes ||
      signature.size() != mldsa44_signature_bytes || public_key.size() != mldsa44_public_key_bytes) {
    return VerifyResult::malformed_input;
  }
  // Some callers represent an empty byte string by a null pointer.
  static constexpr std::uint8_t empty = 0;
  const auto* m = message.empty() ? &empty : reinterpret_cast<const std::uint8_t*>(message.data());
  const auto* c = context.empty() ? &empty : reinterpret_cast<const std::uint8_t*>(context.data());
  const int result = MLD_API_NAMESPACE(verify)(
      reinterpret_cast<const std::uint8_t*>(signature.data()), m, message.size(), c, context.size(),
      reinterpret_cast<const std::uint8_t*>(public_key.data()));
  if (result == 0) {
    return VerifyResult::valid;
  }
  if (result == MLD_ERR_INVALID_SIGNATURE) {
    return VerifyResult::invalid;
  }
  // A backend failure must not masquerade as a mathematical rejection.
  return VerifyResult::backend_error;
}
}  // namespace tos::pq
