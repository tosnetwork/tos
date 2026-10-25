/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "slh_dsa.h"
#include "slhdsa128s.h"
#ifdef TOS_SLHDSA_SHA_NI
#include "slhdsa-sha256.h"
#endif

namespace tos::pq {
const char* slhdsa128s_sha256_backend() noexcept {
#ifdef TOS_SLHDSA_SHA_NI
  return tos_slhdsa_sha256_backend();
#else
  return "portable";
#endif
}

VerifyResult verify_slhdsa128s(std::string_view message, std::string_view context, std::string_view signature,
                               std::string_view public_key) noexcept {
  if (public_key.size() != slhdsa128s_public_key_bytes || signature.size() != slhdsa128s_signature_bytes ||
      message.size() > slhdsa128s_max_message_bytes || context.size() > slhdsa128s_max_context_bytes) {
    return VerifyResult::malformed_input;
  }
  auto bytes = [](std::string_view v) { return reinterpret_cast<const uint8_t*>(v.data()); };
  switch (slh_verify(bytes(message), message.size(), bytes(signature), signature.size(), bytes(context), context.size(),
                     bytes(public_key), &slh_dsa_sha2_128s)) {
    case 1:
      return VerifyResult::valid;
    case 0:
      return VerifyResult::invalid;
    default:
      return VerifyResult::backend_error;
  }
}
}  // namespace tos::pq
