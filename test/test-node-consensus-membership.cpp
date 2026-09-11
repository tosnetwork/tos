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
// Unit test for node_validator_membership, the pure core behind
// NodeConsensusStatus.is_validator. It proves the tri-state is REAL against a live-built
// validator set, so a regression to a hardwired value is caught:
//   - a local key that IS in the set   -> {has_keys=true,  in_set=true}
//   - a local key NOT in the set       -> {has_keys=true,  in_set=false}  (must not be true)
//   - no local keys at all             -> {has_keys=false, in_set=false}  (caller => null)
//   - membership via the permanent set -> same as temp
// The set carries ONLY the member key; the decision follows the key sets PASSED IN, which is
// why membership from live manager keys can never go stale against an online key change.
#include "validator/node-consensus-status.h"

#include "tos/tos-types.h"

#include <cstdio>
#include <set>
#include <utility>
#include <vector>

using namespace tos;

namespace {
Bits256 bits_with_first_byte(td::uint8 b) {
  Bits256 x;
  x.set_zero();
  x.as_slice()[0] = static_cast<char>(b);
  return x;
}

PublicKeyHash short_id_of(const Ed25519_PublicKey& key) {
  return PublicKey{pubkeys::Ed25519{key}}.compute_short_id();
}
}  // namespace

int main() {
  Ed25519_PublicKey pub_member{bits_with_first_byte(0x11)};
  Ed25519_PublicKey pub_outsider{bits_with_first_byte(0x22)};

  // A validator set containing ONLY the member key.
  std::vector<ValidatorDescr> nodes;
  nodes.emplace_back(pub_member, /*weight=*/1);
  block::ValidatorSet set(/*cc_seqno=*/0, ShardIdFull{masterchainId}, std::move(nodes));

  PublicKeyHash member_key = short_id_of(pub_member);
  PublicKeyHash outsider_key = short_id_of(pub_outsider);

  int failures = 0;
  // Real checks, not assert(): assert() is stripped under NDEBUG, which would make this
  // test pass without evaluating anything.
  auto expect = [&](const char *name, std::pair<bool, bool> got, bool want_has, bool want_in) {
    if (got.first != want_has || got.second != want_in) {
      std::printf("FAIL %s: got {has_keys=%d,in_set=%d} want {%d,%d}\n", name, got.first, got.second, want_has,
                  want_in);
      failures++;
    }
  };

  {
    std::set<PublicKeyHash> temp{member_key};
    expect("member_temp_key_in_set", validator::node_validator_membership(set, temp, {}), true, true);
  }
  {
    std::set<PublicKeyHash> temp{outsider_key};
    expect("configured_non_member_not_in_set", validator::node_validator_membership(set, temp, {}), true, false);
  }
  {
    expect("no_local_keys_unknown", validator::node_validator_membership(set, {}, {}), false, false);
  }
  {
    std::set<PublicKeyHash> perm{member_key};
    expect("member_permanent_key_in_set", validator::node_validator_membership(set, {}, perm), true, true);
  }

  if (failures == 0) {
    std::printf("test-node-consensus-membership: 4/4 scenarios OK\n");
    return 0;
  }
  std::printf("test-node-consensus-membership: %d scenario(s) FAILED\n", failures);
  return 1;
}
