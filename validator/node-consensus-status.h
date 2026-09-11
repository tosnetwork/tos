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

#include <set>
#include <utility>

#include "block/validator-set.h"
#include "keys/keys.hpp"

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
inline std::pair<bool, bool> node_validator_membership(const block::ValidatorSet& set,
                                                       const std::set<PublicKeyHash>& temp_keys,
                                                       const std::set<PublicKeyHash>& permanent_keys) {
  bool has_keys = !temp_keys.empty() || !permanent_keys.empty();
  for (const auto& key : temp_keys) {
    if (set.is_validator(key.bits256_value())) {
      return {has_keys, true};
    }
  }
  for (const auto& key : permanent_keys) {
    if (set.is_validator(key.bits256_value())) {
      return {has_keys, true};
    }
  }
  return {has_keys, false};
}

}  // namespace tos::validator
