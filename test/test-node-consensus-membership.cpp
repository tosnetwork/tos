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

#include "block/validator-session-members.h"
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
  auto expect = [&](const char* name, std::pair<bool, bool> got, bool want_has, bool want_in) {
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

    // get_matching_store: the one entry a Simplex group takes a signer from. It hands back
    // the store only when the descriptor names byte-for-byte the key this node holds, and
    // nothing (fail-closed) otherwise.
    const std::string held_pk = held_store->consensus_key().public_key;
    ValidatorDescr matched{pq_id, /*algorithm_id=*/1, held_key, held_pk, /*weight=*/1, bits_with_first_byte(0xc0)};
    check("matching_store_returns_the_held_store", holding.get_matching_store(pq_id, matched) == held_store);

    // The descriptor names a different validator than the one asked for.
    ValidatorDescr other_id{
        tos::ValidatorId{bits_with_first_byte(0xb0)}, 1, held_key, held_pk, 1, bits_with_first_byte(0xc0)};
    check("matching_store_refuses_a_validator_id_mismatch", holding.get_matching_store(pq_id, other_id) == nullptr);

    // Same validator, but the descriptor records a rotated key this node does not hold.
    ValidatorDescr rotated{
        pq_id, 1, key_id_of(*other_store), other_store->consensus_key().public_key, 1, bits_with_first_byte(0xc0)};
    check("matching_store_refuses_a_key_id_mismatch", holding.get_matching_store(pq_id, rotated) == nullptr);

    // Same key id, but a tampered public key: the exact bytes must match.
    std::string tampered_pk = held_pk;
    tampered_pk[0] = static_cast<char>(tampered_pk[0] ^ 0x01);
    ValidatorDescr tampered{pq_id, 1, held_key, tampered_pk, 1, bits_with_first_byte(0xc0)};
    check("matching_store_refuses_a_public_key_mismatch", holding.get_matching_store(pq_id, tampered) == nullptr);

    // An unadmitted algorithm id is refused even with the right key bytes.
    ValidatorDescr wrong_algo{pq_id, /*algorithm_id=*/2, held_key, held_pk, 1, bits_with_first_byte(0xc0)};
    check("matching_store_refuses_a_wrong_algorithm", holding.get_matching_store(pq_id, wrong_algo) == nullptr);

    // A classical descriptor never yields a post-quantum signer.
    ValidatorDescr classical{pub_member, /*weight=*/1};
    check("matching_store_refuses_a_classical_descriptor", holding.get_matching_store(pq_id, classical) == nullptr);

    // No custodied key for this validator at all.
    validator::PqConsensusCustody empty_custody;
    check("matching_store_refuses_when_nothing_is_custodied",
          empty_custody.get_matching_store(pq_id, matched) == nullptr);

    // validate_pq_consensus_descriptor: the one question the manager (before creating a
    // group) and the consensus bus (before starting one) both ask, so they cannot disagree
    // on what a usable consensus key is. It must accept only a well-formed PQ descriptor.
    check("usable_descriptor_is_accepted", block::validate_pq_consensus_descriptor(matched).is_ok());
    check("classical_descriptor_is_refused", block::validate_pq_consensus_descriptor(classical).is_error());
    check("unadmitted_algorithm_is_refused", block::validate_pq_consensus_descriptor(wrong_algo).is_error());

    // A public key of the wrong length cannot be the suite's key.
    ValidatorDescr short_pk{pq_id, 1, held_key, held_pk.substr(0, held_pk.size() - 1), 1, bits_with_first_byte(0xc0)};
    check("short_public_key_is_refused", block::validate_pq_consensus_descriptor(short_pk).is_error());

    // A key id that does not derive from the public key it travels with: here the held
    // key's id is paired with a different (but well-formed) public key.
    ValidatorDescr mismatched_id{
        pq_id, 1, held_key, other_store->consensus_key().public_key, 1, bits_with_first_byte(0xc0)};
    check("key_id_not_deriving_from_public_key_is_refused",
          block::validate_pq_consensus_descriptor(mismatched_id).is_error());

    // A post-quantum descriptor must say where it is reachable; it can never derive a
    // transport identity from its consensus key.
    ValidatorDescr no_addr{pq_id, 1, held_key, held_pk, 1, td::Bits256::zero()};
    check("descriptor_without_a_transport_address_is_refused",
          block::validate_pq_consensus_descriptor(no_addr).is_error());

    // validate_simplex_pq_validator_set: the whole-set preflight the manager runs before a
    // group exists, and the bus repeats as defense-in-depth.
    const auto second_id = tos::ValidatorId{bits_with_first_byte(0xb1)};
    const auto other_key = key_id_of(*other_store);
    const std::string other_pk = other_store->consensus_key().public_key;
    auto set_of = [](std::vector<ValidatorDescr> descrs) {
      return block::ValidatorSet{/*cc_seqno=*/0, ShardIdFull{masterchainId}, std::move(descrs)};
    };

    auto runnable = set_of({matched, ValidatorDescr{second_id, 1, other_key, other_pk, 1, bits_with_first_byte(0xc1)}});
    check("a_post_quantum_set_is_runnable", block::validate_simplex_pq_validator_set(runnable).is_ok());

    auto with_classical = set_of({matched, classical});
    check("a_set_containing_a_classical_member_is_refused",
          block::validate_simplex_pq_validator_set(with_classical).is_error());

    // A second, distinct member that is well-formed except that it states no transport
    // address. It needs its own identity and key: two members sharing either cannot be put
    // in a ValidatorSet at all (its constructor CHECKs both).
    ValidatorDescr unroutable_member{second_id, 1, other_key, other_pk, 1, td::Bits256::zero()};
    auto with_no_addr = set_of({matched, unroutable_member});
    check("a_set_with_an_unroutable_member_is_refused",
          block::validate_simplex_pq_validator_set(with_no_addr).is_error());

    // Two members at one transport address. Everything else about them is distinct, so a
    // shared address is the only thing that can refuse this set.
    //
    // Unlike the two rules below, this one is reachable, and that is exactly why it is
    // here. Decoding refuses a repeated address, but ValidatorSet's constructor does not,
    // so a set built directly -- a test fixture, tooling -- arrives at the preflight with
    // two members the overlay cannot tell apart: it indexes peers by transport identity,
    // the second member replaces the first, and a message authenticated on that transport
    // is then attributed to a validator other than the one whose consensus key signed it.
    ValidatorDescr shares_an_address{second_id, 1, other_key, other_pk, 1, bits_with_first_byte(0xc0)};
    auto with_repeated_addr = set_of({matched, shares_an_address});
    check("a_set_repeating_a_transport_address_is_refused",
          block::validate_simplex_pq_validator_set(with_repeated_addr).is_error());

    // Identity and consensus-key uniqueness are deliberately NOT this helper's job, and
    // there is no case for them here, because no such set can be built: ValidatorSet's
    // constructor CHECKs both (crypto/block/validator-set.cpp:78-85) and a decoded set is
    // refused outright. A duplicate case would abort in the constructor without ever
    // reaching the helper -- a guard no input can trip is decoration, so the helper does
    // not restate the rule. The transport address has no such constructor check, which is
    // what makes the case above reachable and the rule worth stating.

    auto empty = set_of({});
    check("an_empty_set_is_refused", block::validate_simplex_pq_validator_set(empty).is_error());
  }

  if (failures == 0) {
    std::printf("test-node-consensus-membership: all scenarios OK (membership + get_matching_store)\n");
    return 0;
  }
  std::printf("test-node-consensus-membership: %d scenario(s) FAILED\n", failures);
  return 1;
}
