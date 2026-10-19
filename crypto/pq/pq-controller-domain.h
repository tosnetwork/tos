/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// The validator controller's authority domain: its operation, its signed tag, and the
// context that separates its signatures from every other post-quantum authority here.
//
// These three sit apart from the preimage layout in `pq-controller.h` because a signer
// needs only the domain and should not have to pull in cell and bitstring machinery to
// learn a context string. They are still one definition: `pq-controller.h` includes this
// rather than restating them, so the bytes and the domain cannot drift apart.

#include <cstdint>
#include <string_view>

namespace tos::pq {

// Internal message operation, lowercase; signed-preimage domain, uppercase.
inline constexpr std::uint32_t controller_auth_op = 0x50516361;        // "PQca"
inline constexpr std::uint32_t controller_auth_sign_tag = 0x50514341;  // "PQCA"

// The signature context, distinct from every other authority in this system.
inline constexpr std::string_view controller_auth_context = "TOS-VALIDATOR-CONTROLLER-v1";

}  // namespace tos::pq
