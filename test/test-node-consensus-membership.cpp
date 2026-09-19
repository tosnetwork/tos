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
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "tos/tos-types.h"
#include "validator/node-consensus-status.h"

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
  // The call itself has to run, which is exactly what assert() cannot promise here.
  auto check = [&](const char* name, bool ok) {
    if (!ok) {
      std::printf("FAIL %s\n", name);
      failures++;
    }
  };
  auto expect = [&](const char *name, std::pair<bool, bool> got, bool want_has, bool want_in) {
    if (got.first != want_has || got.second != want_in) {
      std::printf("FAIL %s: got {has_keys=%d,in_set=%d} want {%d,%d}\n", name, got.first, got.second, want_has,
                  want_in);
      failures++;
    }
  };

  {
    std::set<PublicKeyHash> temp{member_key};
    expect("member_temp_key_in_set", validator::node_validator_membership(set, temp, {}, {}), true, true);
  }
  {
    std::set<PublicKeyHash> temp{outsider_key};
    expect("configured_non_member_not_in_set", validator::node_validator_membership(set, temp, {}, {}), true, false);
  }
  {
    expect("no_local_keys_unknown", validator::node_validator_membership(set, {}, {}, {}), false, false);
  }
  {
    std::set<PublicKeyHash> perm{member_key};
    expect("member_permanent_key_in_set", validator::node_validator_membership(set, {}, perm, {}), true, true);
  }

  // A post-quantum validator: its identity has nothing to do with any Ed25519 key, and
  // membership follows the consensus key this node actually holds. Custody is taken by
  // handing over a key store, so these cases have to generate real keys; naming an
  // identity and a key identity is not something the type allows.
  {
    auto held_store = std::make_shared<const tos::pq::ValidatorPQKeyStore>(
        tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, '\x01')).value());
    auto other_store = std::make_shared<const tos::pq::ValidatorPQKeyStore>(
        tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, '\x02')).value());

    auto key_id_of = [](const tos::pq::ValidatorPQKeyStore& store) {
      td::Bits256 out;
      const auto& raw = store.consensus_key().key_id;
      std::memcpy(out.data(), raw.data(), raw.size());
      return tos::ConsensusKeyId{out};
    };
    const auto pq_id = tos::ValidatorId{bits_with_first_byte(0xa0)};
    const auto held_key = key_id_of(*held_store);

    // The set records the key this node holds.
    std::vector<ValidatorDescr> pq_nodes;
    pq_nodes.emplace_back(pq_id, /*algorithm_id=*/1, held_key, held_store->consensus_key().public_key,
                          /*weight=*/1, bits_with_first_byte(0xc0));
    block::ValidatorSet pq_set(/*cc_seqno=*/0, ShardIdFull{masterchainId}, std::move(pq_nodes));

    validator::PqConsensusCustody holding;
    check("custody_install_accepts_a_key", holding.install(pq_id, held_store).is_ok());
    expect("pq_custodied_key_is_member", validator::node_validator_membership(pq_set, {}, {}, holding), true, true);

    // Holding a different key for that validator does not: a validator that has rotated
    // away from this key is not us any more, and the key identity is read from the key
    // rather than taken on our word.
    validator::PqConsensusCustody stale;
    check("custody_install_accepts_a_rotated_key", stale.install(pq_id, other_store).is_ok());
    expect("pq_stale_key_is_not_member", validator::node_validator_membership(pq_set, {}, {}, stale), true, false);

    // The back door this phase exists to close: every Ed25519 key in the world, and no
    // custody, must not make this node a post-quantum consensus validator. The keys
    // offered here include ones whose identities are the validator's own identity and
    // its key identity, which is exactly what the old membership rule would have taken.
    std::set<PublicKeyHash> every_ed25519{member_key, outsider_key, PublicKeyHash{pq_id.value},
                                          PublicKeyHash{held_key.value}};
    expect("ed25519_keys_alone_are_not_pq_membership",
           validator::node_validator_membership(pq_set, every_ed25519, every_ed25519, {}), true, false);

    // A store that failed to load is refused. Accepting it silently would leave the caller
    // believing this node custodies a key it cannot sign with.
    validator::PqConsensusCustody absent;
    check("absent_key_store_is_refused", absent.install(pq_id, nullptr).is_error());
    check("refused_store_is_not_custodied", absent.empty());
    expect("absent_key_store_is_not_membership", validator::node_validator_membership(pq_set, {}, {}, absent), false,
           false);

    // And holding the right key for some other validator is not holding it for this one.
    validator::PqConsensusCustody elsewhere;
    check("custody_install_accepts_another_validators_key",
          elsewhere.install(tos::ValidatorId{bits_with_first_byte(0xa9)}, held_store).is_ok());
    expect("custody_of_another_validator_is_not_membership",
           validator::node_validator_membership(pq_set, {}, {}, elsewhere), true, false);
  }

  if (failures == 0) {
    std::printf("test-node-consensus-membership: 10/10 scenarios OK\n");
    return 0;
  }
  std::printf("test-node-consensus-membership: %d scenario(s) FAILED\n", failures);
  return 1;
}
