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
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <variant>
#include <vector>

#include "crypto/pq/consensus-config-json.h"
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

std::shared_ptr<const pq::ValidatorPQKeyStore> key_from(char seed_byte, std::uint32_t expire_at = 0) {
  auto store = pq::ValidatorPQKeyStore::from_seed(std::string(32, seed_byte));
  if (!store) {
    std::printf("FAIL key derivation for seed byte %d\n", seed_byte);
    std::exit(1);
  }
  store->set_expire_at(expire_at);
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
  // There is no override: naming a key only asserts which key the schedule assigns.
  check("naming_the_scheduled_key_signs_with_it",
        index_of(pq::select_stake_key(ab, 9000, 5, &b)) == 1 && index_of(pq::select_stake_key(ab, 999, 5, &a)) == 0);
  check("naming_another_held_key_is_refused_with_the_scheduled_key",
        refused_with(
            pq::select_stake_key(ab, 9000, 5, &a),
            ("the schedule assigns election date 9000 to consensus key " + pq::consensus_key_id_hex(b)).c_str()));
  check("naming_a_key_before_its_window_is_refused",
        refused_with(pq::select_stake_key(ab, 999, 5, &b), "the schedule assigns election date 999"));
  check("naming_an_unheld_key_is_refused",
        refused_with(pq::select_stake_key(ab, 9000, 5, &unknown), "the schedule assigns election date 9000"));
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
  // A cannot be named for that election: the schedule assigns it to B, and says so.
  auto named_a = custody.select_stake_store(validator_id, election, now, id_a);
  check("naming_a_for_bs_election_is_refused",
        named_a.is_error() && named_a.error().message().str().find(
                                  pq::consensus_key_id_hex(key_b->consensus_key().key_id)) != std::string::npos);
  auto named_b = custody.select_stake_store(validator_id, election, now, id_b);
  check("naming_b_for_its_election_signs_with_b", named_b.is_ok() && named_b.ok() == key_b);
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
  // A store whose deadline is not its window's end is refused: the two are one fact.
  check("custody_refuses_a_store_without_the_windows_deadline",
        expiring.install(validator_id, key_a, 0, now).is_error() && expiring.empty());
  const auto expiring_a = key_from('\x0a', now);
  check("custody_of_an_expiring_a", expiring.install(validator_id, expiring_a, 0, now).is_ok());
  check("custody_of_b_beside_it", expiring.install(validator_id, key_b, 10, 0).is_ok());
  check("an_unexpired_key_still_signs",
        expiring.get_matching_store(validator_id, set_with_a[0], now - 1) == expiring_a);
  check("an_expired_key_signs_no_group", expiring.get_matching_store(validator_id, set_with_a[0], now) == nullptr);
  check("an_expired_key_is_not_held_for_use",
        !expiring.holds(validator_id, id_a, now) && expiring.usable_key_ids(validator_id, now).size() == 1);
  check("an_expired_key_is_not_membership", !validator::node_validator_membership(set_a, {}, {}, expiring, now).second);
  check("an_expired_key_signs_no_vote",
        validator::pq_signer_for_set(set_with_a, validator_id, expiring, now).is_error());
  check("an_expired_key_signs_no_named_stake", expiring.select_stake_store(validator_id, 5, now, id_a).is_error());
  check("an_expired_key_is_still_listed_for_removal", expiring.held_keys(validator_id).count(id_a) == 1);

  // A restart after the successor B expired: B is configured but not loaded, and only its
  // window is known. The stake for an election B was scheduled for is refused; the older
  // A, still held, is never signed with in B's place.
  validator::PqConsensusCustody restarted;
  check("restart_holds_a", restarted.install(validator_id, key_a, 0, 0).is_ok());
  check("restart_records_the_expired_successor", restarted.record_unloaded(validator_id, 1, 2).is_ok());
  auto after_b = restarted.select_stake_store(validator_id, 2'000'000'000U, now, std::nullopt);
  check("restart_refuses_the_stake_the_expired_successor_was_scheduled_for",
        after_b.is_error() &&
            after_b.error().message().str().find("(expired and not loaded) expired at 2") != std::string::npos);
  auto before_b = restarted.select_stake_store(validator_id, 0, now, std::nullopt);
  check("restart_still_signs_an_election_before_the_successor_with_a", before_b.is_ok() && before_b.ok() == key_a);
  check("restart_refuses_an_unloaded_window_that_repeats_a_date",
        restarted.record_unloaded(validator_id, 1, 5).is_error() &&
            restarted.install(validator_id, key_c, 1, 0).is_error());
  check("restart_refuses_a_zero_key_id_request",
        restarted.select_stake_store(validator_id, 2'000'000'000U, now, ConsensusKeyId{}).is_error());

  // Removal judged at the moment it takes effect: A never expires and no set lists it; B,
  // the only other key, expires at 100. Admitted at 99 (B still usable), refused at 100
  // (only an expired B would remain) -- the same state, one clock tick apart, as when the
  // engine checks before its hop to the validator manager and the manager acts after it.
  {
    validator::PqConsensusCustody crossing;
    const auto expiring_b = key_from('\x0b', 100);
    check("crossing_holds_a", crossing.install(validator_id, key_a, 0, 0).is_ok());
    check("crossing_holds_b_until_100", crossing.install(validator_id, expiring_b, 50, 100).is_ok());
    const std::vector<std::vector<ValidatorDescr>> no_sets;
    check("removal_of_a_admitted_while_b_is_usable",
          !crossing.removal_refusal(validator_id, id_a, 99, no_sets).has_value());
    auto at_deadline = crossing.removal_refusal(validator_id, id_a, 100, no_sets);
    check("removal_of_a_refused_once_b_expired",
          at_deadline.has_value() &&
              at_deadline->find("every configured consensus key has expired") != std::string::npos);
    check("removal_of_expired_b_is_admitted", !crossing.removal_refusal(validator_id, id_b, 100, no_sets).has_value());
    const std::vector<std::vector<ValidatorDescr>> listing_a{set_with_a};
    check("removal_of_a_listed_key_is_refused",
          crossing.removal_refusal(validator_id, id_a, 99, listing_a).has_value());
    check("removal_of_an_absent_key_is_refused",
          crossing.removal_refusal(validator_id, validator::PqConsensusCustody::key_id_of(*key_c), 99, no_sets)
              .has_value());
  }

  // Removal is per key.
  check("removing_a_key_keeps_the_other", custody.remove_key(validator_id, id_a) &&
                                              !custody.holds(validator_id, id_a, now) &&
                                              custody.holds(validator_id, id_b, now));
  check("removing_an_absent_key_reports_it", !custody.remove_key(validator_id, id_a));
  check("removing_the_last_key_empties_custody", custody.remove_key(validator_id, id_b) && custody.empty());
}

// A scripted wall clock: each reading takes the next value, and the last one repeats.
std::vector<std::int64_t> test_clock_values;
std::size_t test_clock_next = 0;
std::int64_t test_clock() noexcept {
  if (test_clock_values.empty()) {
    return 0;
  }
  const auto index = std::min(test_clock_next, test_clock_values.size() - 1);
  test_clock_next++;
  return test_clock_values[index];
}
void set_test_clock(std::vector<std::int64_t> values) {
  test_clock_values = std::move(values);
  test_clock_next = 0;
  pq::ValidatorPQKeyStore::set_clock_for_test(&test_clock);
}

void deadline_checks() {
  // The hard deadline is the store's own: whatever holds it, it signs nothing from
  // expire_at on, and the boundary is exact.
  const auto now = static_cast<std::uint32_t>(std::time(nullptr));
  auto store = pq::ValidatorPQKeyStore::from_seed(std::string(32, '\x0d'));
  if (!store) {
    check("deadline_key_derivation", false);
    return;
  }
  store->set_expire_at(now + 2);
  check("deadline_boundary_before", !store->expired_at(now + 1));
  check("deadline_boundary_at", store->expired_at(now + 2) && store->expired_at(now + 3));
  check("deadline_signs_before_it", store->sign_consensus("before").has_value() &&
                                        store->sign_config_vote("before").has_value() &&
                                        store->sign_election("before").has_value());
  check("deadline_refused_nothing_before_it", store->signatures_refused_after_expiry() == 0);
  while (static_cast<std::uint32_t>(std::time(nullptr)) < now + 2) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  check("deadline_is_reached", store->expired_now());
  check("deadline_refuses_a_consensus_signature", !store->sign_consensus("after").has_value());
  check("deadline_refuses_a_config_vote", !store->sign_config_vote("after").has_value());
  check("deadline_refuses_an_election_signature", !store->sign_election("after").has_value());
  check("deadline_counts_each_refusal", store->signatures_refused_after_expiry() == 3);
  const auto adnl = filled(0x61);
  const auto owner = filled(0x62);
  check("deadline_refuses_a_stake",
        !pq::sign_stake_authorization(*store, 1, 5, 0x10000, filled(0x51), adnl, owner).has_value());
  // Moving the store keeps its deadline.
  auto moved = std::move(*store);
  check("deadline_survives_a_move", moved.expired_now() && !moved.sign_consensus("moved").has_value());

  auto unbounded = pq::ValidatorPQKeyStore::from_seed(std::string(32, '\x0e'));
  check("no_deadline_signs", unbounded && !unbounded->expired_now() && unbounded->sign_consensus("x").has_value());

  // The deadline inside a signing call, and a clock stepped back, under a test clock.
  // Signing starts at 104 and finishes at 106, with the deadline at 105: the signature is
  // made but never returned.
  auto crossing = pq::ValidatorPQKeyStore::from_seed(std::string(32, '\x0f'));
  if (!crossing) {
    check("deadline_crossing_key_derivation", false);
    return;
  }
  crossing->set_expire_at(105);
  set_test_clock({104, 106});
  check("a_signature_finishing_after_the_deadline_is_discarded", !crossing->sign_consensus("start 104").has_value());
  check("a_discarded_signature_retires_the_key", crossing->retired());
  set_test_clock({104});
  check("a_clock_stepped_back_does_not_revive_the_key", !crossing->sign_consensus("back at 104").has_value() &&
                                                            !crossing->sign_election("back at 104").has_value() &&
                                                            crossing->expired_now());
  auto stepped = pq::ValidatorPQKeyStore::from_seed(std::string(32, '\x10'));
  stepped->set_expire_at(105);
  set_test_clock({106});
  check("refused_at_106", !stepped->sign_consensus("at 106").has_value());
  set_test_clock({104});
  check("still_refused_after_the_clock_goes_back_to_104", !stepped->sign_consensus("at 104").has_value());
  auto fresh = pq::ValidatorPQKeyStore::from_seed(std::string(32, '\x11'));
  fresh->set_expire_at(105);
  check("a_key_never_seen_expired_signs_at_104", fresh->sign_consensus("at 104").has_value() && !fresh->retired());
  pq::ValidatorPQKeyStore::set_clock_for_test(nullptr);
}

bool json_refused(const char* text, const char* phrase) {
  std::string copy = text;
  auto json = td::json_decode(td::MutableSlice(copy));
  if (json.is_error()) {
    std::printf("FAIL json fixture does not parse: %s\n", text);
    return false;
  }
  auto verdict = pq::check_consensus_key_json(json.ok());
  return verdict.has_value() && verdict->find(phrase) != std::string::npos;
}

bool json_accepted(const char* text) {
  std::string copy = text;
  auto json = td::json_decode(td::MutableSlice(copy));
  return json.is_ok() && !pq::check_consensus_key_json(json.ok()).has_value();
}

void json_checks() {
  check("json_accepts_no_binding", json_accepted(R"({"extraconfig": {"state_serializer_enabled": true}})"));
  check("json_accepts_the_single_form",
        json_accepted(R"({"extraconfig": {"pq_consensus": {"@type": "engine.validator.pqConsensus",
          "validator_id": "AA==", "consensus_key_file": "/k/a", "keys": []}}})"));
  check("json_accepts_the_multi_form",
        json_accepted(R"({"extraconfig": {"pq_consensus": {"validator_id": "AA==", "consensus_key_file": "",
          "keys": [{"@type": "engine.validator.pqConsensusKey", "consensus_key_file": "/k/a", "valid_from": 0,
          "expire_at": 0}, {"consensus_key_file": "/k/b", "valid_from": "2000000000", "expire_at": 0}]}}})"));
  check("json_refuses_a_misspelt_window_field",
        json_refused(R"({"extraconfig": {"pq_consensus": {"validator_id": "AA==", "keys": [
          {"consensus_key_file": "/k/b", "validFrom": 2000000000, "valid_from": 0, "expire_at": 0}]}}})",
                     "validFrom is not a field"));
  check("json_refuses_a_missing_window_field",
        json_refused(R"({"extraconfig": {"pq_consensus": {"validator_id": "AA==", "keys": [
          {"consensus_key_file": "/k/b", "expire_at": 0}]}}})",
                     "valid_from is missing"));
  check("json_refuses_an_unknown_binding_field",
        json_refused(R"({"extraconfig": {"pq_consensus": {"validator_id": "AA==", "consensus_key_file": "/k/a",
          "comment": 1}}})",
                     "comment is not a field"));
  check("json_refuses_both_forms_at_once",
        json_refused(R"({"extraconfig": {"pq_consensus": {"validator_id": "AA==", "consensus_key_file": "/k/a",
          "keys": [{"consensus_key_file": "/k/b", "valid_from": 5, "expire_at": 0}]}}})",
                     "both a single"));
  check("json_refuses_no_key", json_refused(R"({"extraconfig": {"pq_consensus": {"validator_id": "AA==",
          "consensus_key_file": "", "keys": []}}})",
                                            "names no consensus key"));
  check("json_refuses_a_negative_window",
        json_refused(R"({"extraconfig": {"pq_consensus": {"validator_id": "AA==", "keys": [
          {"consensus_key_file": "/k/b", "valid_from": -5, "expire_at": 0}]}}})",
                     "not a unix time"));
  check("json_refuses_a_window_beyond_int32",
        json_refused(R"({"extraconfig": {"pq_consensus": {"validator_id": "AA==", "keys": [
          {"consensus_key_file": "/k/b", "valid_from": 2147483648, "expire_at": 0}]}}})",
                     "not a unix time"));
  check("json_refuses_another_key_type",
        json_refused(R"({"extraconfig": {"pq_consensus": {"validator_id": "AA==", "keys": [
          {"@type": "engine.validator.pqConsensus", "consensus_key_file": "/k/b", "valid_from": 1, "expire_at": 0}]}}})",
                     "is not a engine.validator.pqConsensusKey"));
  check(
      "json_refuses_a_missing_validator",
      json_refused(R"({"extraconfig": {"pq_consensus": {"consensus_key_file": "/k/a"}}})", "validator_id is missing"));
}

}  // namespace

int main() {
  schedule_checks();
  custody_checks();
  deadline_checks();
  json_checks();
  if (failures == 0) {
    std::printf("test-pq-consensus-key-rotation: all scenarios OK\n");
    return 0;
  }
  std::printf("test-pq-consensus-key-rotation: %d scenario(s) FAILED\n", failures);
  return 1;
}
