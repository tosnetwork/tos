/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// Which of a node's post-quantum consensus keys is used for what.
//
// A validator keeps one identity (its controller account) and rotates the consensus key
// that identity signs with. A rotation from key A to key B has no single safe instant to
// switch at: the validator set that is running may still list A for this validator,
// while the controller, once rebound to B, accepts only stakes signed by B. So a node
// holds both for a while, and each signature it makes picks its key by a rule rather
// than by whichever key happens to be loaded:
//
//   - a validator group (and a vote cast as a member of a set) signs with the key whose
//     identity the set's descriptor for this validator records. Nothing here chooses it;
//     the set does, and a set that lists a key this node does not hold gets no signer.
//   - a stake for the election starting at `election_date` signs with the key the
//     schedule assigns to that election, and only that key: the key with the greatest
//     `valid_from` that is not after the election date. Keys are thereby assigned half-open election ranges
//     [valid_from, next key's valid_from). Two keys with the same `valid_from` would make
//     that assignment ambiguous, so a schedule holding them is refused outright.
//   - a key whose `expire_at` has passed is not used for anything, and is not silently
//     replaced by an older key either: the stake is refused, and a group whose set lists
//     it gets no signer.
//
// This is pure: no clock, no file, no chain state. Callers pass the time and the keys.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace tos::pq {

using ConsensusKeyIdBytes = std::array<std::uint8_t, 32>;

// One consensus key as the schedule sees it: its identity (derived from the seed, never
// configured) and its validity window.
struct ConsensusKeyWindow {
  ConsensusKeyIdBytes key_id{};
  // The first election date (unix time) this key may authorize a stake for. 0 admits
  // every election, which is what a node with a single key configures.
  std::uint32_t valid_from = 0;
  // The unix time from which the node no longer uses this key at all. 0: never expires.
  std::uint32_t expire_at = 0;
  // False for a configured key whose seed was not loaded (it had expired): its identity
  // is unknown, and it can be scheduled but never chosen.
  bool loaded = true;
};

// A node holds the key it is rotating away from and the one it is rotating to; a few
// more leave room for a key prepared ahead. Anything beyond is not a rotation.
inline constexpr std::size_t max_node_consensus_keys = 8;

constexpr bool consensus_key_expired(std::uint32_t expire_at, std::uint32_t now) noexcept {
  return expire_at != 0 && now >= expire_at;
}

inline std::string consensus_key_id_hex(const ConsensusKeyIdBytes& key_id) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(2 * key_id.size());
  for (const auto byte : key_id) {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 15]);
  }
  return out;
}

// Validity windows alone, before any key is loaded: what a configuration can be refused
// for without reading a seed. Returns why it is refused, or nothing.
inline std::optional<std::string> check_consensus_key_windows(const std::vector<ConsensusKeyWindow>& keys) {
  if (keys.empty()) {
    return std::string("no consensus key is configured");
  }
  if (keys.size() > max_node_consensus_keys) {
    return "at most " + std::to_string(max_node_consensus_keys) + " consensus keys may be held at once, not " +
           std::to_string(keys.size());
  }
  for (std::size_t i = 0; i < keys.size(); i++) {
    const auto& key = keys[i];
    if (key.expire_at != 0 && key.expire_at <= key.valid_from) {
      return "a consensus key expires at " + std::to_string(key.expire_at) + ", not after its window opens at " +
             std::to_string(key.valid_from);
    }
    for (std::size_t j = 0; j < i; j++) {
      if (keys[j].valid_from == key.valid_from) {
        return "two consensus keys are valid from the same election date " + std::to_string(key.valid_from) +
               ": which one signs a stake for it would be ambiguous";
      }
    }
  }
  return std::nullopt;
}

// The whole schedule, once every key has been loaded and its identity derived.
inline std::optional<std::string> check_consensus_key_schedule(const std::vector<ConsensusKeyWindow>& keys) {
  if (auto refused = check_consensus_key_windows(keys)) {
    return refused;
  }
  for (std::size_t i = 0; i < keys.size(); i++) {
    for (std::size_t j = 0; j < i; j++) {
      if (keys[j].key_id == keys[i].key_id) {
        return "consensus key " + consensus_key_id_hex(keys[i].key_id) + " is configured twice";
      }
    }
  }
  return std::nullopt;
}

// A key as a node configuration names it: where its seed is, and its window. Its
// identity is not configured; it is derived from the seed when the key is loaded.
struct ConfiguredConsensusKey {
  std::string key_file;
  std::uint32_t valid_from = 0;
  std::uint32_t expire_at = 0;
};

// What a node loads at startup from its configured keys, decided before any seed is read:
// the indices of the keys to load, or why the configuration is refused. Refused: no key,
// too many, an empty or repeated file path, a window `check_consensus_key_windows`
// refuses, or every key already expired (a node configured as a validator that can sign
// nothing is misconfigured, and must not come up quietly as an observer). A key that has
// expired is not loaded: it will never be used, and its seed may already be gone.
inline std::variant<std::vector<std::size_t>, std::string> plan_consensus_key_load(
    const std::vector<ConfiguredConsensusKey>& keys, std::uint32_t now) {
  std::vector<ConsensusKeyWindow> windows;
  windows.reserve(keys.size());
  for (std::size_t i = 0; i < keys.size(); i++) {
    if (keys[i].key_file.empty()) {
      return std::string("a consensus key is configured with no key file");
    }
    for (std::size_t j = 0; j < i; j++) {
      if (keys[j].key_file == keys[i].key_file) {
        return "consensus key file " + keys[i].key_file + " is configured twice";
      }
    }
    windows.push_back(ConsensusKeyWindow{{}, keys[i].valid_from, keys[i].expire_at});
  }
  if (auto refused = check_consensus_key_windows(windows)) {
    return *refused;
  }
  std::vector<std::size_t> load;
  for (std::size_t i = 0; i < keys.size(); i++) {
    if (!consensus_key_expired(keys[i].expire_at, now)) {
      load.push_back(i);
    }
  }
  if (load.empty()) {
    return std::string("every configured consensus key has expired");
  }
  return load;
}

// The key a stake for the election at `election_date` is signed with: its index in
// `keys`, or why there is none. `keys` is a schedule `check_consensus_key_schedule`
// accepted.
//
// Always the key the schedule assigns to the election -- the greatest `valid_from` not
// after it -- and no other: there is no override. `requested`, when given, is the
// caller's statement of which key it expects; if the schedule assigns a different key
// the stake is refused, naming the key the schedule does assign, so an operator's
// expectation and the node's schedule cannot disagree silently. A scheduled key that has
// expired is a refusal, never a fall back to an older key: the controller accepts the key
// it is bound to and no other, and an older key is the one a rotation moved away from.
inline std::variant<std::size_t, std::string> select_stake_key(const std::vector<ConsensusKeyWindow>& keys,
                                                               std::uint32_t election_date, std::uint32_t now,
                                                               const ConsensusKeyIdBytes* requested) {
  const auto unusable = [&](const ConsensusKeyWindow& key) -> std::optional<std::string> {
    const auto name = key.loaded ? consensus_key_id_hex(key.key_id) : std::string("(expired and not loaded)");
    if (consensus_key_expired(key.expire_at, now)) {
      return "consensus key " + name + " expired at " + std::to_string(key.expire_at);
    }
    if (key.valid_from > election_date) {
      return "consensus key " + name + " is valid only from election date " + std::to_string(key.valid_from) +
             ", after " + std::to_string(election_date);
    }
    if (key.expire_at != 0 && key.expire_at <= election_date) {
      return "consensus key " + name + " expires at " + std::to_string(key.expire_at) + ", before election date " +
             std::to_string(election_date);
    }
    return std::nullopt;
  };

  std::optional<std::size_t> scheduled;
  for (std::size_t i = 0; i < keys.size(); i++) {
    if (keys[i].valid_from <= election_date && (!scheduled || keys[i].valid_from > keys[*scheduled].valid_from)) {
      scheduled = i;
    }
  }
  if (!scheduled) {
    return "no consensus key is valid for election date " + std::to_string(election_date);
  }
  const auto& chosen = keys[*scheduled];
  if (requested != nullptr && !(chosen.loaded && chosen.key_id == *requested)) {
    const auto name = chosen.loaded ? consensus_key_id_hex(chosen.key_id) : std::string("(expired and not loaded)");
    return "the schedule assigns election date " + std::to_string(election_date) + " to consensus key " + name +
           ", not to " + consensus_key_id_hex(*requested);
  }
  if (auto why = unusable(chosen)) {
    return *why + "; it is the key scheduled for election date " + std::to_string(election_date);
  }
  return *scheduled;
}

}  // namespace tos::pq
