/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// A validator's request to enter an election, signed.
//
// This is the one place the bytes of that request are assembled and signed. The node's
// control query and the operator tool both call it and nothing else, so what a stake
// commits to cannot change for one without changing for the other -- the "parallel road"
// a review warned about, where the tested tool and the untested node quietly diverge.
//
// The key identity is taken from the signer here, once. The two call sites used to copy
// it themselves with `memcpy(dst, src, key_id.size())`, and a Bits256 sizes in bits, so
// 256 bytes went into a 32-byte buffer -- a stack overflow that printed a correct
// signature and then aborted on return. Deriving it in one place removes the copy, and
// the class of bug, from both.

#include <cstdint>
#include <cstring>
#include <optional>

#include "common/bitstring.h"

#include "consensus-pq-signer.h"
#include "pq-consensus.h"
#include "pq-elector.h"

namespace tos::pq {

struct StakeAuthorization {
  td::Bits256 key_id;
  ConsensusPQSignature signature;
};

// Sign a stake for `election` under the election domain, naming `owner` as the account
// the money belongs to. Nothing here consults a validator set: a stake is how a node
// enters one, so it must be signable before the node is in any.
//
// Returns nullopt on a zero transport address or owner, a weight factor below one, or a
// backend failure -- the same preconditions the node and the tool enforced separately,
// now enforced once.
inline std::optional<StakeAuthorization> sign_stake_authorization(
    const ValidatorPQKeyStore& store, std::int32_t global_id, std::uint32_t election, std::uint32_t max_factor,
    const td::Bits256& validator_id, const td::Bits256& adnl, const td::Bits256& owner) noexcept {
  if (adnl.is_zero() || owner.is_zero() || max_factor < 0x10000) {
    return std::nullopt;
  }
  // The key identity, from the signer. `ConsensusPQKey::key_id` is the 32-byte array, so
  // its own size is the count to copy -- never the destination Bits256's, which is 256.
  const auto& derived = store.consensus_key().key_id;
  td::Bits256 key_id;
  std::memcpy(key_id.data(), derived.data(), derived.size());

  const auto preimage = stake_preimage(global_id, election, max_factor, validator_id, owner,
                                       static_cast<std::uint16_t>(PQAlgorithmId::mldsa44), key_id, adnl);
  auto signature = store.sign_election(preimage);
  if (!signature.has_value()) {
    return std::nullopt;
  }
  return StakeAuthorization{key_id, std::move(*signature)};
}

}  // namespace tos::pq
