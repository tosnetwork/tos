/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// The wire constants of the post-quantum election and governance messages, and the exact
// bytes their signatures are made over.
//
// These are the last things that are cheap to change. A contract, a node and a piece of
// tooling each build these bytes for themselves; if their field orders drift, a signature
// made by one verifies for none of the others, and the failure looks like a bad key
// rather than a bad layout. So the layout lives here once, and the shared vectors beside
// it hold the bytes this produces.
//
// Every field is big-endian, which is what a contract's store_uint writes, and every
// preimage is byte-aligned, which the signature instructions require.

#include <cstdint>
#include <cstring>
#include <string>

#include "common/bitstring.h"

namespace tos::pq {

// Internal message operations, lowercase; signed-preimage domains, uppercase.
inline constexpr std::uint32_t elector_pq_stake_op = 0x50517374;            // "PQst"
inline constexpr std::uint32_t elector_pq_stake_sign_tag = 0x50515354;      // "PQST"
inline constexpr std::uint32_t config_pq_vote_op = 0x5051766f;              // "PQvo"
inline constexpr std::uint32_t config_pq_vote_sign_tag = 0x5051564f;        // "PQVO"
inline constexpr std::uint32_t elector_pq_complaint_op = 0x5051636f;        // "PQco"
inline constexpr std::uint32_t elector_pq_complaint_sign_tag = 0x5051434f;  // "PQCO"

namespace detail {
inline void append_be(std::string& out, std::uint64_t value, std::size_t bytes) {
  for (std::size_t i = bytes; i-- > 0;) {
    out.push_back(static_cast<char>((value >> (i * 8)) & 0xff));
  }
}
inline void append_bits256(std::string& out, const td::Bits256& value) {
  out.append(reinterpret_cast<const char*>(value.data()), 32);
}
}  // namespace detail

// What a stake request signs. The validator identity is the controlling account the
// contract saw, and the key identity is derived by the contract from the key presented:
// neither is taken from the request, and binding both is what stops a request naming one
// validator while carrying another's key.
inline std::string stake_preimage(std::int32_t global_id, std::uint32_t stake_at, std::uint32_t max_factor,
                                  const td::Bits256& validator_id, std::uint16_t algorithm_id,
                                  const td::Bits256& key_id, const td::Bits256& adnl_addr) {
  std::string out;
  out.reserve(114);
  detail::append_be(out, elector_pq_stake_sign_tag, 4);
  detail::append_be(out, static_cast<std::uint32_t>(global_id), 4);
  detail::append_be(out, stake_at, 4);
  detail::append_be(out, max_factor, 4);
  detail::append_bits256(out, validator_id);
  detail::append_be(out, algorithm_id, 2);
  detail::append_bits256(out, key_id);
  detail::append_bits256(out, adnl_addr);
  return out;
}

// What a configuration vote signs. The current set's identity is bound so a vote
// collected under one validator set cannot be replayed under the next.
inline std::string config_vote_preimage(std::int32_t global_id, const td::Bits256& validator_set_id,
                                        const td::Bits256& validator_id, std::uint16_t idx,
                                        const td::Bits256& proposal_hash) {
  std::string out;
  out.reserve(106);
  detail::append_be(out, config_pq_vote_sign_tag, 4);
  detail::append_be(out, static_cast<std::uint32_t>(global_id), 4);
  detail::append_bits256(out, validator_set_id);
  detail::append_bits256(out, validator_id);
  detail::append_be(out, idx, 2);
  detail::append_bits256(out, proposal_hash);
  return out;
}

// What a complaint vote signs. Same shape as a configuration vote, plus the election the
// complaint belongs to, and a distinct domain so neither can be replayed as the other.
inline std::string complaint_vote_preimage(std::int32_t global_id, const td::Bits256& validator_set_id,
                                           const td::Bits256& validator_id, std::uint16_t idx,
                                           std::uint32_t election_id, const td::Bits256& complaint_hash) {
  std::string out;
  out.reserve(110);
  detail::append_be(out, elector_pq_complaint_sign_tag, 4);
  detail::append_be(out, static_cast<std::uint32_t>(global_id), 4);
  detail::append_bits256(out, validator_set_id);
  detail::append_bits256(out, validator_id);
  detail::append_be(out, idx, 2);
  detail::append_be(out, election_id, 4);
  detail::append_bits256(out, complaint_hash);
  return out;
}

}  // namespace tos::pq
