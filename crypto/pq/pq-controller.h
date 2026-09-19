/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// What a validator controller's post-quantum root authorizes, and the exact bytes it
// signs.
//
// A controller is the root of a validator's authority: it owns the stake, it is the
// stable validator identity, and it is what replaces an operational consensus key. Its
// root key therefore signs under a domain of its own, and this file is the one place the
// layout of that signature's message lives.
//
// The appenders come from pq-elector.h so that the two never drift apart; nothing else
// is shared, and a controller depends on no part of the validator descriptor.

#include <cstdint>
#include <string>

#include "common/bitstring.h"
#include "crypto/pq/pq-elector.h"

namespace tos::pq {

// Internal message operation, lowercase; signed-preimage domain, uppercase.
inline constexpr std::uint32_t controller_auth_op = 0x50516361;        // "PQca"
inline constexpr std::uint32_t controller_auth_sign_tag = 0x50514341;  // "PQCA"

// The signature context, distinct from every other authority in this system.
inline constexpr std::string_view controller_auth_context = "TOS-VALIDATOR-CONTROLLER-v1";

// What a controller root signs. Exactly 93 bytes.
//
// `controller_id` is the controller's own account id, which the contract takes from its
// own address and never from the request. `payload_hash` is the level-zero commitment to
// the action being authorized, so an authorization binds the action without carrying it:
// a first stake's payload holds a pruned state-init proof, whose own shape and address
// commitment the elector checks separately.
inline std::string controller_auth_preimage(std::int32_t global_id, const td::Bits256& controller_id,
                                            std::uint64_t epoch, std::uint64_t nonce, std::uint32_t valid_until,
                                            std::uint8_t kind, const td::Bits256& payload_hash) {
  std::string out;
  out.reserve(93);
  detail::append_be(out, controller_auth_sign_tag, 4);
  detail::append_be(out, static_cast<std::uint32_t>(global_id), 4);
  detail::append_bits256(out, controller_id);
  detail::append_be(out, epoch, 8);
  detail::append_be(out, nonce, 8);
  detail::append_be(out, valid_until, 4);
  detail::append_be(out, kind, 1);
  detail::append_bits256(out, payload_hash);
  return out;
}

}  // namespace tos::pq
