/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <utility>

#include "block/validator-set.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "keys/keys.hpp"
#include "td/utils/Status.h"

namespace tos::validator {

// Pure membership decision behind NodeConsensusStatus.is_validator, extracted from the
// manager so it can be unit-tested without the actor. Returns {has_local_keys,
// is_validator_in_set}:
//   - has_local_keys is false when this node holds no validator keys at all -> the caller
//     reports is_validator as null/unknown, never a false negative;
//   - is_validator_in_set is true iff one of the PASSED-IN key sets is a member of `set`.
// It decides membership from the key sets given to it (the manager passes its LIVE
// temp_/permanent_ sets each call), so it can never go stale against an online key change.
// Membership here is set membership of a configured identity; it does NOT assert that the
// node is actively signing or has recovered full consensus participation.
// The post-quantum consensus keys this node actually holds, by the validator identity
// each belongs to.
//
// An entry cannot be made by naming an identity and a key identity: it takes the key
// store itself, and the key identity is read back out of the key rather than supplied.
// That is the difference between custodying a key and claiming to. A node that cannot
// sign for a validator must not conclude that it is that validator.
class PqConsensusCustody {
 public:
  // Refuses rather than accepting an absent key. Dropping it silently would leave a caller
  // that failed to load a key believing this node custodies one, which is the same mistake
  // as claiming an identity without holding its key. [[nodiscard]] so that ignoring the
  // answer is not something a caller can do by habit.
  [[nodiscard]] td::Status install(const tos::ValidatorId& validator_id,
                                   std::shared_ptr<const tos::pq::ValidatorPQKeyStore> store) {
    if (!store) {
      return td::Status::Error("no post-quantum consensus key store to custody for this validator");
    }
    stores_[validator_id] = std::move(store);
    return td::Status::OK();
  }
  void remove(const tos::ValidatorId& validator_id) {
    stores_.erase(validator_id);
  }
  bool empty() const {
    return stores_.empty();
  }
  // The identity of the key held for this validator, derived from the key itself when
  // the store was built. Nothing here is taken on the caller's word.
  std::optional<tos::ConsensusKeyId> held_key_id(const tos::ValidatorId& validator_id) const {
    auto it = stores_.find(validator_id);
    if (it == stores_.end()) {
      return std::nullopt;
    }
    td::Bits256 key_id;
    const auto& raw = it->second->consensus_key().key_id;
    std::memcpy(key_id.data(), raw.data(), raw.size());
    return tos::ConsensusKeyId{key_id};
  }

 private:
  std::map<tos::ValidatorId, std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> stores_;
};

// The validator identity this node is a member of `set` as, if any.
//
// A post-quantum member is only ours when we custody its consensus key and that key is
// the one the set currently records for it. An Ed25519 key can never answer for one:
// its identity is unrelated, so owning network or operator keys does not make a node a
// consensus validator. A classical member is still matched by its key, whose identity
// is what the set records for it.
inline std::optional<tos::ValidatorId> local_consensus_member(const block::ValidatorSet& set,
                                                              const std::set<PublicKeyHash>& temp_keys,
                                                              const std::set<PublicKeyHash>& permanent_keys,
                                                              const PqConsensusCustody& pq_custody) {
  for (const auto& descr : set.export_vector()) {
    if (descr.is_pq()) {
      auto held = pq_custody.held_key_id(descr.validator_id);
      if (held && *held == descr.key_id) {
        return descr.validator_id;
      }
      continue;
    }
    const auto classical = PublicKeyHash{descr.validator_id.value};
    if (temp_keys.count(classical) != 0 || permanent_keys.count(classical) != 0) {
      return descr.validator_id;
    }
  }
  return std::nullopt;
}

inline std::pair<bool, bool> node_validator_membership(const block::ValidatorSet& set,
                                                       const std::set<PublicKeyHash>& temp_keys,
                                                       const std::set<PublicKeyHash>& permanent_keys,
                                                       const PqConsensusCustody& pq_custody) {
  // Holding any key at all is what separates "not a validator" from "cannot tell yet";
  // custodying a post-quantum consensus key counts as holding one.
  bool has_keys = !temp_keys.empty() || !permanent_keys.empty() || !pq_custody.empty();
  return {has_keys, local_consensus_member(set, temp_keys, permanent_keys, pq_custody).has_value()};
}

}  // namespace tos::validator
