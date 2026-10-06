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

    Copyright 2026 TOS Blockchain Teams
*/
// A node that holds several post-quantum consensus keys for one validator, so the key can
// rotate from A to B without a moment at which the node holds only the wrong one.
//
// What is checked, in the order a rotation exercises it:
//   - the key schedule: which configurations are refused (no key, too many, a window that
//     closes before it opens, two keys valid from one election date, one key twice, a
//     repeated file, every key expired), and which key signs the stake for an election;
//   - custody: several keys held at once, a refused install changing nothing, an expired
//     key answering for nothing;
//   - the signing paths the node takes, end to end on real keys: holding A and B, a set
//     that lists A gets A as its group and vote signer while the stake for the next
//     election is signed with B, and that signature verifies under B and not under A; a
//     set listing a key the node does not hold, or holds expired, gets no signer at all.
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>

#include "crypto/pq/consensus-key-schedule.h"
#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-consensus.h"
#include "crypto/pq/pq-stake-authorization.h"
#include "tos/tos-types.h"
#include "validator/node-consensus-status.h"

using namespace tos;

namespace {

int failures = 0;

void check(const char* name, bool ok) {
  if (!ok) {
    std::printf("FAIL %s\n", name);
    failures++;
  }
}

Bits256 filled(td::uint8 b) {
  Bits256 x;
  x.set_zero();
  x.as_slice()[0] = static_cast<char>(b);
  return x;
}

pq::ConsensusKeyIdBytes id_bytes(td::uint8 b) {
  pq::ConsensusKeyIdBytes out{};
  out[0] = b;
  return out;
}

std::shared_ptr<const pq::ValidatorPQKeyStore> key_from(char seed_byte) {
  auto store = pq::ValidatorPQKeyStore::from_seed(std::string(32, seed_byte));
  if (!store) {
    std::printf("FAIL key derivation for seed byte %d\n", seed_byte);
    std::exit(1);
  }
  return std::make_shared<const pq::ValidatorPQKeyStore>(std::move(*store));
}

ValidatorDescr descriptor(const ValidatorId& id, const pq::ValidatorPQKeyStore& key, td::uint8 addr) {
  return ValidatorDescr{id,
                        static_cast<td::uint16>(key.consensus_key().algorithm_id),
                        validator::PqConsensusCustody::key_id_of(key),
                        key.consensus_key().public_key,
                        1,
                        filled(addr)};
}

bool refused_with(const std::optional<std::string>& verdict, const char* phrase) {
  return verdict.has_value() && verdict->find(phrase) != std::string::npos;
}

template <class T>
bool refused_with(const std::variant<T, std::string>& verdict, const char* phrase) {
  return std::holds_alternative<std::string>(verdict) &&
         std::get<std::string>(verdict).find(phrase) != std::string::npos;
}

void schedule_checks() {
  using pq::ConsensusKeyWindow;
  // The configurations a node refuses before reading any seed.
  check("schedule_refuses_no_key", refused_with(pq::check_consensus_key_windows({}), "no consensus key"));
  std::vector<ConsensusKeyWindow> nine;
  for (td::uint8 i = 0; i < 9; i++) {
    nine.push_back(ConsensusKeyWindow{id_bytes(i), static_cast<std::uint32_t>(i) * 100, 0});
  }
  check("schedule_refuses_more_than_the_capacity", refused_with(pq::check_consensus_key_windows(nine), "at most 8"));
  nine.pop_back();
  check("schedule_accepts_exactly_the_capacity", !pq::check_consensus_key_schedule(nine).has_value());
  check("schedule_refuses_a_window_that_closes_before_it_opens",
        refused_with(pq::check_consensus_key_windows({{id_bytes(1), 100, 100}}), "not after its window"));
  check(
      "schedule_refuses_two_keys_from_one_election",
      refused_with(pq::check_consensus_key_windows({{id_bytes(1), 0, 0}, {id_bytes(2), 0, 0}}), "same election date"));
  check(
      "schedule_refuses_one_key_twice",
      refused_with(pq::check_consensus_key_schedule({{id_bytes(1), 0, 0}, {id_bytes(1), 100, 0}}), "configured twice"));
  check("schedule_accepts_a_rotation",
        !pq::check_consensus_key_schedule({{id_bytes(1), 0, 0}, {id_bytes(2), 1000, 0}}).has_value());

  // What a start loads.
  using pq::ConfiguredConsensusKey;
  check("load_refuses_an_empty_file_name", refused_with(pq::plan_consensus_key_load({{"", 0, 0}}, 10), "no key file"));
  check("load_refuses_a_repeated_file",
        refused_with(pq::plan_consensus_key_load({{"/k/a", 0, 0}, {"/k/a", 100, 0}}, 10), "configured twice"));
  check("load_refuses_when_every_key_expired",
        refused_with(pq::plan_consensus_key_load({{"/k/a", 0, 50}, {"/k/b", 60, 70}}, 100), "every configured"));
  check("load_refuses_an_ambiguous_schedule",
        refused_with(pq::plan_consensus_key_load({{"/k/a", 5, 0}, {"/k/b", 5, 0}}, 1), "same election date"));
  auto plan = pq::plan_consensus_key_load({{"/k/a", 0, 50}, {"/k/b", 40, 0}}, 100);
  check("load_skips_an_expired_key", std::holds_alternative<std::vector<std::size_t>>(plan) &&
                                         std::get<std::vector<std::size_t>>(plan) == std::vector<std::size_t>{1});
  auto single = pq::plan_consensus_key_load({{"/k/a", 0, 0}}, 4'000'000'000U);
  check("load_keeps_a_single_unbounded_key", std::holds_alternative<std::vector<std::size_t>>(single) &&
                                                 std::get<std::vector<std::size_t>>(single).size() == 1);

  // Which key signs the stake for an election.
  const auto index_of = [](const std::variant<std::size_t, std::string>& v) -> long {
    return std::holds_alternative<std::size_t>(v) ? static_cast<long>(std::get<std::size_t>(v)) : -1;
  };
  // One key valid for everything: the configuration of a node that never rotates signs
  // every election with it, whatever the date -- the behavior before several keys existed.
  const std::vector<ConsensusKeyWindow> one{{id_bytes(1), 0, 0}};
  check("single_key_signs_any_election", index_of(pq::select_stake_key(one, 0, 5, nullptr)) == 0 &&
                                             index_of(pq::select_stake_key(one, 4'000'000'000U, 5, nullptr)) == 0);

  const std::vector<ConsensusKeyWindow> ab{{id_bytes(0xa), 0, 0}, {id_bytes(0xb), 1000, 0}};
  check("before_the_successor_window_the_old_key_signs", index_of(pq::select_stake_key(ab, 999, 5, nullptr)) == 0);
  check("from_the_successor_window_the_successor_signs", index_of(pq::select_stake_key(ab, 1000, 5, nullptr)) == 1);
  check("later_elections_stay_with_the_successor", index_of(pq::select_stake_key(ab, 9000, 5, nullptr)) == 1);
  // The order the keys are listed in decides nothing.
  const std::vector<ConsensusKeyWindow> ba{{id_bytes(0xb), 1000, 0}, {id_bytes(0xa), 0, 0}};
  check("listing_order_decides_nothing", index_of(pq::select_stake_key(ba, 1000, 5, nullptr)) == 0 &&
                                             index_of(pq::select_stake_key(ba, 999, 5, nullptr)) == 1);

  const auto a = id_bytes(0xa);
  const auto b = id_bytes(0xb);
  const auto unknown = id_bytes(0xc);
  check("a_named_key_overrides_the_schedule", index_of(pq::select_stake_key(ab, 9000, 5, &a)) == 0);
  check("a_named_key_must_cover_the_election",
        refused_with(pq::select_stake_key(ab, 999, 5, &b), "valid only from election date 1000"));
  check("a_named_key_must_be_held", refused_with(pq::select_stake_key(ab, 9000, 5, &unknown), "not held"));
  check("no_key_covers_an_election_before_every_window",
        refused_with(pq::select_stake_key(std::vector<ConsensusKeyWindow>{{id_bytes(1), 500, 0}}, 499, 5, nullptr),
                     "no consensus key is valid"));

  // An expired scheduled key is refused, never replaced by the older key the rotation
  // moved away from.
  const std::vector<ConsensusKeyWindow> b_expired{{id_bytes(0xa), 0, 0}, {id_bytes(0xb), 1000, 2000}};
  check("an_expired_scheduled_key_is_refused_not_replaced",
        refused_with(pq::select_stake_key(b_expired, 9000, 2500, nullptr), "expired at 2000"));
  check("a_named_expired_key_is_refused", refused_with(pq::select_stake_key(b_expired, 1500, 2500, &b), "expired"));
  check("a_key_expiring_by_the_election_is_refused",
        refused_with(pq::select_stake_key(b_expired, 2000, 1500, nullptr), "before election date 2000"));
  check("an_unexpired_key_before_its_expiry_signs",
        index_of(pq::select_stake_key(b_expired, 1500, 1200, nullptr)) == 1);
}

void custody_checks() {
  const auto key_a = key_from('\x0a');
  const auto key_b = key_from('\x0b');
  const auto key_c = key_from('\x0c');
  const auto id_a = validator::PqConsensusCustody::key_id_of(*key_a);
  const auto id_b = validator::PqConsensusCustody::key_id_of(*key_b);
  const auto validator_id = ValidatorId{filled(0x51)};
  constexpr td::uint32 now = 1'000'000;

  validator::PqConsensusCustody custody;
  check("custody_holds_the_old_key", custody.install(validator_id, key_a, 0, 0).is_ok());
  check("custody_holds_the_successor_beside_it", custody.install(validator_id, key_b, now + 100, 0).is_ok());
  check("custody_holds_both", custody.holds(validator_id, id_a, now) && custody.holds(validator_id, id_b, now) &&
                                  custody.usable_key_ids(validator_id, now).size() == 2);

  // A key whose window repeats another's is refused, and nothing changes.
  check("custody_refuses_an_ambiguous_window",
        custody.install(validator_id, key_c, now + 100, 0).is_error() && custody.held_keys(validator_id).size() == 2);
  check("custody_refuses_an_absent_store", custody.install(validator_id, nullptr, 7, 0).is_error());
  // Installing a key it holds replaces that key's window rather than holding it twice.
  check("custody_reinstall_replaces_the_window", custody.install(validator_id, key_b, now + 200, 0).is_ok() &&
                                                     custody.held_keys(validator_id).size() == 2 &&
                                                     custody.held_keys(validator_id).at(id_b).valid_from == now + 200);

  // The engine-level paths, on real keys. The running set lists A; the stake for the
  // election at now + 300 (after B's window opens) is due.
  const auto set_with_a = std::vector<ValidatorDescr>{descriptor(validator_id, *key_a, 0xc0),
                                                      descriptor(ValidatorId{filled(0x52)}, *key_c, 0xc1)};
  block::ValidatorSet set_a(0, ShardIdFull{masterchainId}, set_with_a);
  check("a_set_listing_a_counts_the_node_as_its_member",
        validator::node_validator_membership(set_a, {}, {}, custody, now).second);
  check("the_group_for_a_set_listing_a_signs_with_a",
        custody.get_matching_store(validator_id, set_with_a[0], now) == key_a);
  auto vote_signer = validator::pq_signer_for_set(set_with_a, validator_id, custody, now);
  check("a_vote_counted_by_a_set_listing_a_is_signed_with_a",
        vote_signer.is_ok() && vote_signer.ok().signer == key_a && vote_signer.ok().index == 0);

  const td::uint32 election = now + 300;
  auto stake_signer = custody.select_stake_store(validator_id, election, now, std::nullopt);
  check("the_stake_for_the_next_election_is_signed_with_b", stake_signer.is_ok() && stake_signer.ok() == key_b);
  if (stake_signer.is_ok()) {
    const auto adnl = filled(0x61);
    const auto owner = filled(0x62);
    const td::int32 global_id = 77;
    auto signed_stake =
        pq::sign_stake_authorization(*stake_signer.ok(), global_id, election, 0x10000, validator_id.value, adnl, owner);
    check("the_stake_signature_is_made", signed_stake.has_value());
    if (signed_stake) {
      check("the_stake_names_key_b", signed_stake->key_id == id_b.value);
      const auto preimage =
          pq::stake_preimage(global_id, election, 0x10000, validator_id.value, owner,
                             static_cast<std::uint16_t>(pq::PQAlgorithmId::mldsa44), id_b.value, adnl);
      check("the_stake_verifies_under_b",
            pq::verify_mldsa44(preimage, pq::validator_election_context, signed_stake->signature.signature,
                               key_b->consensus_key().public_key) == pq::VerifyResult::valid);
      check("the_stake_does_not_verify_under_a",
            pq::verify_mldsa44(preimage, pq::validator_election_context, signed_stake->signature.signature,
                               key_a->consensus_key().public_key) == pq::VerifyResult::invalid);
    }
  }
  // Before the controller is rebound, an operator may still name A for that election.
  auto named_a = custody.select_stake_store(validator_id, election, now, id_a);
  check("a_named_key_signs_the_stake", named_a.is_ok() && named_a.ok() == key_a);
  // And a stake for the current election, before B's window, stays with A.
  auto current = custody.select_stake_store(validator_id, now, now, std::nullopt);
  check("the_stake_before_bs_window_is_signed_with_a", current.is_ok() && current.ok() == key_a);

  // Once the next set lists B, the group for it signs with B.
  const auto set_with_b = std::vector<ValidatorDescr>{descriptor(validator_id, *key_b, 0xc0)};
  check("the_group_for_a_set_listing_b_signs_with_b",
        custody.get_matching_store(validator_id, set_with_b[0], now) == key_b);

  // A set listing a key the node does not hold: no signer, no membership, exactly as
  // with a single key. The group is refused.
  validator::PqConsensusCustody only_b;
  check("custody_of_b_alone", only_b.install(validator_id, key_b, 0, 0).is_ok());
  check("a_set_listing_an_unheld_key_gets_no_group_signer",
        only_b.get_matching_store(validator_id, set_with_a[0], now) == nullptr);
  check("a_set_listing_an_unheld_key_gets_no_vote_signer",
        only_b.get_matching_store(validator_id, set_with_a[0], now) == nullptr &&
            validator::pq_signer_for_set(set_with_a, validator_id, only_b, now).is_error());
  check("a_set_listing_an_unheld_key_is_not_membership",
        !validator::node_validator_membership(set_a, {}, {}, only_b, now).second);
  check("a_set_not_naming_the_validator_gets_no_vote_signer",
        validator::pq_signer_for_set(set_with_a, ValidatorId{filled(0x53)}, custody, now).is_error());

  // An expired key answers for nothing: not as a group signer, not as a member, not for a
  // vote, not for a stake, and the other held key is never substituted for it.
  validator::PqConsensusCustody expiring;
  check("custody_of_an_expiring_a", expiring.install(validator_id, key_a, 0, now).is_ok());
  check("custody_of_b_beside_it", expiring.install(validator_id, key_b, 10, 0).is_ok());
  check("an_unexpired_key_still_signs", expiring.get_matching_store(validator_id, set_with_a[0], now - 1) == key_a);
  check("an_expired_key_signs_no_group", expiring.get_matching_store(validator_id, set_with_a[0], now) == nullptr);
  check("an_expired_key_is_not_held_for_use",
        !expiring.holds(validator_id, id_a, now) && expiring.usable_key_ids(validator_id, now).size() == 1);
  check("an_expired_key_is_not_membership", !validator::node_validator_membership(set_a, {}, {}, expiring, now).second);
  check("an_expired_key_signs_no_vote",
        validator::pq_signer_for_set(set_with_a, validator_id, expiring, now).is_error());
  check("an_expired_key_signs_no_named_stake", expiring.select_stake_store(validator_id, 5, now, id_a).is_error());
  check("an_expired_key_is_still_listed_for_removal", expiring.held_keys(validator_id).count(id_a) == 1);

  // Removal is per key.
  check("removing_a_key_keeps_the_other", custody.remove_key(validator_id, id_a) &&
                                              !custody.holds(validator_id, id_a, now) &&
                                              custody.holds(validator_id, id_b, now));
  check("removing_an_absent_key_reports_it", !custody.remove_key(validator_id, id_a));
  check("removing_the_last_key_empties_custody", custody.remove_key(validator_id, id_b) && custody.empty());
}

}  // namespace

int main() {
  schedule_checks();
  custody_checks();
  if (failures == 0) {
    std::printf("test-pq-consensus-key-rotation: all scenarios OK\n");
    return 0;
  }
  std::printf("test-pq-consensus-key-rotation: %d scenario(s) FAILED\n", failures);
  return 1;
}
