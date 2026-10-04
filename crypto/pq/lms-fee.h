/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "mldsa44.h"

// Verification of one-level HSS (RFC 8554) signatures for the request-bound rescue fee gate.
// Exactly one profile is admitted: LMS_SHA256_M32_H20 / LMOTS_SHA256_N32_W4, SHA-256, n = m = 32.
namespace tos::pq {
inline constexpr std::size_t lms_fee_public_key_bytes = 4 + 4 + 4 + 16 + 32;  // HSS L=1
inline constexpr std::size_t lms_fee_max_signature_bytes = 4 + 4 + (4 + 32 + 67 * 32) + 4 + 20 * 32;  // 2,832
inline constexpr std::size_t lms_fee_max_message_bytes = 8192;

// Worst-case SHA-256 compressions needed to verify any signature on a message of this length
// under this public key, or nullopt for an unsupported profile or oversized message. Used to
// charge before verifying, so an invalid signature costs as much as the most expensive valid one.
std::optional<std::uint32_t> lms_fee_worst_compressions(std::string_view public_key,
                                                        std::size_t message_bytes) noexcept;

VerifyResult verify_lms_fee(std::string_view message, std::string_view signature, std::string_view public_key) noexcept;
}  // namespace tos::pq
