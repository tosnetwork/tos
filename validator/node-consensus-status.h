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
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "block/validator-set.h"
#include "common/errorcode.h"
#include "crypto/pq/consensus-key-schedule.h"
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
//
// A validator may have several keys custodied at once, so that a consensus key rotation
// has no moment at which the node holds only the wrong one: the key a running set lists
// stays held while the key the controller has been rebound to signs the next stake. Each
// key carries the window `consensus-key-schedule.h` describes. Which key signs is decided
// by the validator set (for a group and a vote) or by that schedule (for a stake), never
// by the order the keys were loaded in. A key whose `expire_at` has passed stays held but
// is never used, and every question below takes the current time to decide that.
class PqConsensusCustody {
 public:
  struct HeldKey {
    std::shared_ptr<const tos::pq::ValidatorPQKeyStore> store;
    td::uint32 valid_from = 0;
    td::uint32 expire_at = 0;
  };

  // Refuses rather than accepting an absent key. Dropping it silently would leave a caller
  // that failed to load a key believing this node custodies one, which is the same mistake
  // as claiming an identity without holding its key. Also refuses a key whose window, with
  // the keys already held for this validator, makes a schedule `check_consensus_key_schedule`
  // refuses (two keys valid from one election date, too many keys, a window that closes
  // before it opens); nothing is changed then. Installing a key already held replaces its
  // window. [[nodiscard]] so that ignoring the answer is not something a caller can do by
  // habit.
  [[nodiscard]] td::Status install(const tos::ValidatorId& validator_id,
                                   std::shared_ptr<const tos::pq::ValidatorPQKeyStore> store, td::uint32 valid_from,
                                   td::uint32 expire_at) {
    if (!store) {
      return td::Status::Error("no post-quantum consensus key store to custody for this validator");
    }
    // The window's end and the store's own signing deadline are one fact stated twice; a
    // store that would go on signing past its window is refused, so the hard deadline
    // holds at every signing point and not only at these lookups.
    if (store->expire_at() != expire_at) {
      return td::Status::Error("the consensus key store's signing deadline differs from its window");
    }
    const auto key_id = key_id_of(*store);
    // A key this process has already seen expire stays retired: removing it and adding it
    // again, from the same seed, does not bring it back.
    if (tos::pq::consensus_key_retired(bytes_of(key_id))) {
      return td::Status::Error("post-quantum consensus key " + key_id.value.to_hex() +
                               " was retired in this process when it expired; it cannot be held again");
    }
    std::vector<tos::pq::ConsensusKeyWindow> schedule;
    auto it = stores_.find(validator_id);
    if (it != stores_.end()) {
      for (const auto& [held_id, held] : it->second) {
        if (held_id != key_id) {
          schedule.push_back(window_of(held_id, held));
        }
      }
    }
    schedule.push_back(tos::pq::ConsensusKeyWindow{bytes_of(key_id), valid_from, expire_at});
    if (auto refused = tos::pq::check_consensus_key_schedule(schedule)) {
      return td::Status::Error("post-quantum consensus key " + key_id.value.to_hex() + " refused: " + *refused);
    }
    if (auto refused = tos::pq::check_consensus_key_windows(with_unloaded(validator_id, schedule))) {
      return td::Status::Error("post-quantum consensus key " + key_id.value.to_hex() + " refused: " + *refused);
    }
    stores_[validator_id][key_id] = HeldKey{std::move(store), valid_from, expire_at};
    return td::Status::OK();
  }
  // A configured key that was not loaded because it had expired. It signs nothing, but
  // its window still belongs to the schedule: without it, a stake for an election the
  // expired key was scheduled for would fall to the older key the rotation moved away
  // from. Refused when it would make the schedule invalid, as `install` is.
  [[nodiscard]] td::Status record_unloaded(const tos::ValidatorId& validator_id, td::uint32 valid_from,
                                           td::uint32 expire_at) {
    std::vector<tos::pq::ConsensusKeyWindow> schedule;
    auto it = stores_.find(validator_id);
    if (it != stores_.end()) {
      for (const auto& [held_id, held] : it->second) {
        schedule.push_back(window_of(held_id, held));
      }
    }
    schedule = with_unloaded(validator_id, schedule);
    schedule.push_back(tos::pq::ConsensusKeyWindow{{}, valid_from, expire_at});
    if (auto refused = tos::pq::check_consensus_key_windows(schedule)) {
      return td::Status::Error("an unloaded consensus key's window refused: " + *refused);
    }
    unloaded_[validator_id].push_back({valid_from, expire_at});
    return td::Status::OK();
  }
  // Every key held for this validator.
  void remove(const tos::ValidatorId& validator_id) {
    stores_.erase(validator_id);
    unloaded_.erase(validator_id);
  }
  // One key; whether it was held.
  bool remove_key(const tos::ValidatorId& validator_id, const tos::ConsensusKeyId& key_id) {
    auto it = stores_.find(validator_id);
    if (it == stores_.end()) {
      return false;
    }
    const bool removed = it->second.erase(key_id) != 0;
    if (it->second.empty()) {
      stores_.erase(it);
    }
    return removed;
  }
  bool empty() const {
    return stores_.empty();
  }
  // Every key held for this validator with its window, expired or not, by key identity.
  // For reporting, and for the checks a caller makes before removing one.
  std::map<tos::ConsensusKeyId, HeldKey> held_keys(const tos::ValidatorId& validator_id) const {
    auto it = stores_.find(validator_id);
    if (it == stores_.end()) {
      return {};
    }
    return it->second;
  }
  // Whether this node holds `key_id` for this validator and may use it at `now`. The
  // identity compared is the one derived from the key when the store was built; nothing
  // here is taken on the caller's word.
  bool holds(const tos::ValidatorId& validator_id, const tos::ConsensusKeyId& key_id, td::uint32 now) const {
    auto it = stores_.find(validator_id);
    if (it == stores_.end()) {
      return false;
    }
    auto held = it->second.find(key_id);
    return held != it->second.end() && held->second.store && !expired(held->first, held->second, now);
  }
  // The identities of the keys usable for this validator at `now`.
  std::vector<tos::ConsensusKeyId> usable_key_ids(const tos::ValidatorId& validator_id, td::uint32 now) const {
    std::vector<tos::ConsensusKeyId> out;
    auto it = stores_.find(validator_id);
    if (it == stores_.end()) {
      return out;
    }
    for (const auto& [key_id, held] : it->second) {
      if (held.store && !expired(key_id, held, now)) {
        out.push_back(key_id);
      }
    }
    return out;
  }

  // The store to sign a validator's consensus messages with, returned only when a key
  // this node custodies for `validator_id`, unexpired at `now`, is byte-for-byte the one
  // the descriptor records -- the admitted algorithm, the exact 32-byte key id, and the
  // exact 1312-byte public key. This is the one entry a Simplex group takes a signer
  // from, and it is fail-closed by construction: a validator_id match with a key not
  // held, an expired key, a different public key, an Ed25519 key, or no custodied key all
  // return nothing, so a node never signs consensus with a key the set does not record
  // for it, and never falls back to another held key or to the network keyring.
  std::shared_ptr<const tos::pq::ValidatorPQKeyStore> get_matching_store(const tos::ValidatorId& validator_id,
                                                                         const tos::ValidatorDescr& descr,
                                                                         td::uint32 now) const {
    if (!descr.is_pq() || !(descr.validator_id == validator_id)) {
      return nullptr;
    }
    auto it = stores_.find(validator_id);
    if (it == stores_.end()) {
      return nullptr;
    }
    auto entry = it->second.find(descr.key_id);
    if (entry == it->second.end() || !entry->second.store) {
      return nullptr;
    }
    if (expired(entry->first, entry->second, now)) {
      return nullptr;
    }
    const auto& held = entry->second.store->consensus_key();
    if (static_cast<td::uint16>(held.algorithm_id) != descr.algorithm_id) {
      return nullptr;
    }
    // Both are the 32-byte key identity; compare exactly 32 bytes. (descr.key_id.value is a
    // Bits256 whose size() counts bits, so it is never used as a byte count here.) The map
    // is keyed by the same derived identity; this compares the store that is about to be
    // returned with the descriptor itself, not only its map key.
    static_assert(std::tuple_size<std::decay_t<decltype(held.key_id)>>::value == 32);
    if (std::memcmp(held.key_id.data(), descr.key_id.value.data(), 32) != 0) {
      return nullptr;
    }
    if (held.public_key != descr.pq_public_key) {
      return nullptr;
    }
    return entry->second.store;
  }

  // The store a stake for the election at `election_date` is signed with: always the key
  // the schedule assigns (`tos::pq::select_stake_key`); `requested`, when given, must be
  // that key or the stake is refused. No validator set is consulted: a stake is how a
  // validator enters one.
  td::Result<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> select_stake_store(
      const tos::ValidatorId& validator_id, td::uint32 election_date, td::uint32 now,
      const std::optional<tos::ConsensusKeyId>& requested) const {
    auto it = stores_.find(validator_id);
    if (it == stores_.end() || it->second.empty()) {
      return td::Status::Error("no post-quantum consensus key is custodied for this validator");
    }
    std::vector<tos::pq::ConsensusKeyWindow> schedule;
    std::vector<std::shared_ptr<const tos::pq::ValidatorPQKeyStore>> stores;
    std::vector<bool> retired;
    for (const auto& [key_id, held] : it->second) {
      schedule.push_back(window_of(key_id, held));
      stores.push_back(held.store);
      retired.push_back(expired(key_id, held, now));
    }
    // Unloaded (expired) keys take part in the choice and, chosen, refuse: they have no
    // store, and their place in the schedule is never handed to another key.
    schedule = with_unloaded(validator_id, schedule);
    stores.resize(schedule.size());
    std::optional<tos::pq::ConsensusKeyIdBytes> wanted;
    if (requested) {
      wanted = bytes_of(*requested);
    }
    auto chosen = tos::pq::select_stake_key(schedule, election_date, now, wanted ? &*wanted : nullptr);
    if (std::holds_alternative<std::string>(chosen)) {
      return td::Status::Error(std::get<std::string>(chosen));
    }
    const auto index = std::get<std::size_t>(chosen);
    if (index >= stores.size() || !stores[index]) {
      return td::Status::Error("the consensus key scheduled for election date " + std::to_string(election_date) +
                               " expired and is not loaded");
    }
    if (index < retired.size() && retired[index]) {
      return td::Status::Error("the consensus key scheduled for election date " + std::to_string(election_date) +
                               " has expired");
    }
    return stores[index];
  }

  // Whether a held key is expired for every purpose at `now` (see `expired`): the one
  // question every caller asks before treating a key as removable or usable, so that a
  // key retired in this process is never judged by its timestamp alone.
  bool key_expired(const tos::ValidatorId& validator_id, const tos::ConsensusKeyId& key_id, td::uint32 now) const {
    auto it = stores_.find(validator_id);
    if (it == stores_.end()) {
      return false;
    }
    auto held = it->second.find(key_id);
    return held != it->second.end() && expired(held->first, held->second, now);
  }

  // Whether a configured key is to be reported as expired at `now`. A held key is judged
  // by custody first -- which retires it if its window has closed at `now` -- so that a
  // key reported expired is never revived by a clock stepped back afterwards; only a key
  // that is not held (not loaded, or of no known identity) falls back to its timestamp.
  bool report_expired(const tos::ValidatorId& validator_id, const std::optional<tos::ConsensusKeyId>& key_id,
                      td::uint32 expire_at, td::uint32 now) const {
    if (key_id) {
      auto it = stores_.find(validator_id);
      if (it != stores_.end() && it->second.count(*key_id) != 0) {
        return key_expired(validator_id, *key_id, now);
      }
    }
    return tos::pq::consensus_key_expired(expire_at, now);
  }

  // Why removing `key_id` at `now` must be refused, or nothing. One clock reading, and the
  // process's retired keys, decide everything: the key itself is not refused once expired
  // or retired, and is refused while usable if any of `sets` lists it for this validator;
  // and the keys that would remain must include one usable at that same `now`, so a
  // removal admitted a moment before a remaining key's deadline is refused if it takes
  // effect after it. The validator manager asks this at the moment it removes the key,
  // after any check the caller made earlier.
  std::optional<std::string> removal_refusal(const tos::ValidatorId& validator_id, const tos::ConsensusKeyId& key_id,
                                             td::uint32 now,
                                             const std::vector<std::vector<tos::ValidatorDescr>>& sets) const {
    auto it = stores_.find(validator_id);
    if (it == stores_.end() || it->second.count(key_id) == 0) {
      return std::string("no such post-quantum consensus key is custodied");
    }
    if (!expired(key_id, it->second.at(key_id), now)) {
      for (const auto& members : sets) {
        for (const auto& descr : members) {
          if (descr.is_pq() && descr.validator_id == validator_id && descr.key_id == key_id) {
            return std::string(
                "consensus key is listed for this validator by a current, previous or next validator set");
          }
        }
      }
    }
    for (const auto& [held_id, held] : it->second) {
      if (held_id != key_id && held.store && !expired(held_id, held, now)) {
        return std::nullopt;
      }
    }
    return std::string(
        "removing it would leave only expired consensus keys; every configured consensus key has expired");
  }

  // The identity a store derives, as the set records key identities.
  static tos::ConsensusKeyId key_id_of(const tos::pq::ValidatorPQKeyStore& store) {
    td::Bits256 key_id;
    const auto& raw = store.consensus_key().key_id;
    static_assert(std::tuple_size<std::decay_t<decltype(raw)>>::value == 32);
    std::memcpy(key_id.data(), raw.data(), raw.size());
    return tos::ConsensusKeyId{key_id};
  }

 private:
  // Expired for every purpose: this process has already seen it expire
  // (`tos::pq::consensus_key_retired`), whatever `now` says; or its window has closed at
  // the caller's `now`, which retires it from then on -- with that same reading, never a
  // second one -- so that a clock stepped back afterwards does not bring it back.
  static bool expired(const tos::ConsensusKeyId& key_id, const HeldKey& held, td::uint32 now) {
    const auto id = bytes_of(key_id);
    if (tos::pq::consensus_key_retired(id)) {
      return true;
    }
    if (tos::pq::consensus_key_expired(held.expire_at, now)) {
      tos::pq::retire_expired_consensus_key(id);
      return true;
    }
    return false;
  }
  static tos::pq::ConsensusKeyIdBytes bytes_of(const tos::ConsensusKeyId& key_id) {
    tos::pq::ConsensusKeyIdBytes out{};
    std::memcpy(out.data(), key_id.value.data(), out.size());
    return out;
  }
  static tos::pq::ConsensusKeyWindow window_of(const tos::ConsensusKeyId& key_id, const HeldKey& held) {
    return tos::pq::ConsensusKeyWindow{bytes_of(key_id), held.valid_from, held.expire_at};
  }

  std::vector<tos::pq::ConsensusKeyWindow> with_unloaded(const tos::ValidatorId& validator_id,
                                                         std::vector<tos::pq::ConsensusKeyWindow> schedule) const {
    auto it = unloaded_.find(validator_id);
    if (it != unloaded_.end()) {
      for (const auto& [valid_from, expire_at] : it->second) {
        schedule.push_back(tos::pq::ConsensusKeyWindow{{}, valid_from, expire_at, false});
      }
    }
    return schedule;
  }

  std::map<tos::ValidatorId, std::map<tos::ConsensusKeyId, HeldKey>> stores_;
  std::map<tos::ValidatorId, std::vector<std::pair<td::uint32, td::uint32>>> unloaded_;
};

// Where `validator_id` stands in a set's members, and the held key that signs for it there:
// the key the member's descriptor records, provided this node custodies exactly that key
// unexpired at `now`. A member whose descriptor records any other key -- one rotated to and
// not yet held, or one held but expired -- gets no signer, and never another held key.
// This is what a node's votes, cast as a member of a set, take their signer from.
struct PqSetSigner {
  std::size_t index = 0;
  tos::ValidatorDescr descr;
  std::shared_ptr<const tos::pq::ValidatorPQKeyStore> signer;
};
inline td::Result<PqSetSigner> pq_signer_for_set(const std::vector<tos::ValidatorDescr>& members,
                                                 const tos::ValidatorId& validator_id,
                                                 const PqConsensusCustody& pq_custody, td::uint32 now) {
  for (std::size_t index = 0; index < members.size(); index++) {
    const auto& descr = members[index];
    if (!descr.is_pq() || descr.validator_id != validator_id) {
      continue;
    }
    auto signer = pq_custody.get_matching_store(validator_id, descr, now);
    if (!signer) {
      // The identity is ours and the key is not one this node can sign with: the set
      // lists a key this node does not hold, or one whose custody has expired. Nothing here
      // can sign for this set, and the node goes on serving as an ordinary one.
      return td::Status::Error(tos::ErrorCode::notready,
                               "the set records consensus key " + descr.key_id.value.to_hex() +
                                   " for this validator, which this node does not hold unexpired");
    }
    return PqSetSigner{index, descr, std::move(signer)};
  }
  return td::Status::Error(tos::ErrorCode::notready, "not a validator of the set");
}

// The validator identity this node is a member of `set` as, if any.
//
// A post-quantum member is only ours when we custody its consensus key and that key is
// the one the set currently records for it. An Ed25519 key can never answer for one:
// its identity is unrelated, so owning network or operator keys does not make a node a
// consensus validator. A classical member is still matched by its key, whose identity
// is what the set records for it.
//
// `now` is the local unix time: a custodied key that has expired answers for nothing.
inline bool local_consensus_descriptor(const tos::ValidatorDescr& descr, const std::set<PublicKeyHash>& temp_keys,
                                       const std::set<PublicKeyHash>& permanent_keys,
                                       const PqConsensusCustody& pq_custody, td::uint32 now) {
  if (descr.is_pq()) {
    return pq_custody.holds(descr.validator_id, descr.key_id, now);
  }
  const auto classical = PublicKeyHash{descr.validator_id.value};
  return temp_keys.count(classical) != 0 || permanent_keys.count(classical) != 0;
}

inline std::optional<tos::ValidatorId> local_consensus_member(const block::ValidatorSet& set,
                                                              const std::set<PublicKeyHash>& temp_keys,
                                                              const std::set<PublicKeyHash>& permanent_keys,
                                                              const PqConsensusCustody& pq_custody, td::uint32 now) {
  for (const auto& descr : set.export_vector()) {
    if (local_consensus_descriptor(descr, temp_keys, permanent_keys, pq_custody, now)) {
      return descr.validator_id;
    }
  }
  return std::nullopt;
}

inline std::pair<bool, bool> node_validator_membership(const block::ValidatorSet& set,
                                                       const std::set<PublicKeyHash>& temp_keys,
                                                       const std::set<PublicKeyHash>& permanent_keys,
                                                       const PqConsensusCustody& pq_custody, td::uint32 now) {
  // Holding any key at all is what separates "not a validator" from "cannot tell yet";
  // custodying a post-quantum consensus key counts as holding one.
  bool has_keys = !temp_keys.empty() || !permanent_keys.empty() || !pq_custody.empty();
  return {has_keys, local_consensus_member(set, temp_keys, permanent_keys, pq_custody, now).has_value()};
}

}  // namespace tos::validator
