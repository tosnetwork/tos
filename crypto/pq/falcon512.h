/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include "mldsa44.h"
namespace tos::pq {
inline constexpr std::size_t falcon512_public_key_bytes = 897;
inline constexpr std::size_t falcon512_signature_bytes = 666;
inline constexpr std::size_t falcon512_secret_key_bytes = 1281;
inline constexpr std::size_t falcon512_max_message_bytes = 8192;
VerifyResult verify_falcon512_padded(std::string_view message, std::string_view signature,
                                   std::string_view public_key) noexcept;
}
