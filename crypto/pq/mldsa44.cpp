/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <atomic>
#include <cstdint>

#include "mldsa44.h"
#include "mldsa_native.h"

namespace tos::pq {
static_assert(MLDSA44_PUBLICKEYBYTES == mldsa44_public_key_bytes);
static_assert(MLDSA44_BYTES == mldsa44_signature_bytes);

namespace {
std::atomic<std::uint64_t> verification_calls{0};
}

VerifyResult verify_mldsa44(std::string_view message, std::string_view context,
                          std::string_view signature, std::string_view public_key) noexcept {
  verification_calls.fetch_add(1, std::memory_order_relaxed);
  if (message.size() > mldsa44_max_message_bytes || context.size() > mldsa44_max_context_bytes ||
      signature.size() != mldsa44_signature_bytes || public_key.size() != mldsa44_public_key_bytes) {
    return VerifyResult::malformed_input;
  }
  // Some callers represent an empty byte string by a null pointer.
  static constexpr std::uint8_t empty = 0;
  const auto* m = message.empty() ? &empty : reinterpret_cast<const std::uint8_t*>(message.data());
  const auto* c = context.empty() ? &empty : reinterpret_cast<const std::uint8_t*>(context.data());
  // The public header cleans up its internal namespace-prefix macro.
  // Call the fixed symbol declared under our pinned build configuration.
  const int result = tos_mldsa44_native_verify(
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

std::uint64_t mldsa44_verification_calls_for_test() noexcept {
  return verification_calls.load(std::memory_order_relaxed);
}

void reset_mldsa44_verification_calls_for_test() noexcept {
  verification_calls.store(0, std::memory_order_relaxed);
}
}  // namespace tos::pq
