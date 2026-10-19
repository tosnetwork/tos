/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include "mldsa44.h"

// PROTOTYPE. Pure SLH-DSA-SHA2-128s (FIPS 205) verification with an explicit context, for the
// wallet rescue root. Verify only.
namespace tos::pq {
inline constexpr std::size_t slhdsa128s_public_key_bytes = 32;
inline constexpr std::size_t slhdsa128s_signature_bytes = 7856;
inline constexpr std::size_t slhdsa128s_max_message_bytes = 8192;
inline constexpr std::size_t slhdsa128s_max_context_bytes = 255;
VerifyResult verify_slhdsa128s(std::string_view message, std::string_view context, std::string_view signature,
                               std::string_view public_key) noexcept;
}  // namespace tos::pq
