/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include <cstddef>
#include <string_view>

namespace tos::pq {
inline constexpr std::size_t mldsa44_public_key_bytes = 1312;
inline constexpr std::size_t mldsa44_signature_bytes = 2420;
inline constexpr std::size_t mldsa44_max_message_bytes = 8192;
inline constexpr std::size_t mldsa44_max_context_bytes = 255;

enum class VerifyResult { invalid, valid, malformed_input, backend_error };

// Pure ML-DSA-44 external interface. No implicit prehash or application context.
// The caller owns each buffer for the duration of this synchronous call.
VerifyResult verify_mldsa44(std::string_view message, std::string_view context,
                          std::string_view signature, std::string_view public_key) noexcept;
}  // namespace tos::pq
