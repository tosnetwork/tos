/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// Pointing a stopped node at its consensus key.
//
// A validator's `<db>/config.json` names the validator it signs for and the file its
// consensus seed is in (`extraconfig.pq_consensus`). The engine writes that file itself
// and rewrites it whenever its configuration changes, so this edits it only while no node
// runs on the database, and writes it the way the engine does: the same TL schema, the
// same JSON encoding, a temporary file flushed and renamed over the old one.
//
// Exclusion is a lock both sides take: the engine holds `<db>/config.json.lock` from
// before it reads its configuration until it exits, and the binder holds it for its whole
// read-modify-write. A running node makes the binder refuse; a node started during the
// edit refuses to start.
//
// This is operator tooling. The node reads the binding and shares only the lock's name.

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace tos::pq {

// The configuration lock inside a database root. The engine and the binder must agree on
// this name and on nothing else.
inline constexpr char node_config_lock_name[] = "config.json.lock";

struct NodeConsensusBinding {
  std::string db_root;                          // the engine's -D directory; holds config.json
  std::string key_file;                         // absolute path the node will load the seed from
  std::array<std::uint8_t, 32> validator_id{};  // the controller's account id
  bool replace = false;                         // allow replacing a different existing binding
};

struct NodeConsensusBindingResult {
  std::array<std::uint8_t, 32> key_id{};  // what the key file derives, never what was typed
  std::string config_path;                // <db_root>/config.json
};

enum class NodeBindingOutcome {
  refused,              // nothing was written; `why` says why
  unchanged,            // the same binding was already there; nothing was written
  applied,              // the new configuration is in place and its directory flushed
  applied_not_durable,  // in place, but the directory flush failed (`why`): a crash
                        // before the file system writes it back may lose the change
};

// Parse a validator id as an operator has it: 64 hexadecimal digits, or the controller's
// masterchain address `-1:` followed by them. Refuses any other workchain and the zero id,
// which the engine refuses at start.
bool parse_validator_id(std::string_view text, std::array<std::uint8_t, 32>& out, std::string& why);

// Bind `binding.key_file` and `binding.validator_id` into `<binding.db_root>/config.json`.
// The id is taken as given: `parse_validator_id` is what refuses a zero one.
//
// Both locks (the configuration lock, and the cell database's when it exists) are held
// for the whole read-modify-write. Refuses, writing nothing, when either is held
// elsewhere, when a config.json.tmp from an interrupted engine write is present, when
// the configuration is not a regular file owned by this user, when it holds anything the
// engine's schema would drop, when a different binding is there and `replace` is not set,
// or when the file's group cannot be kept. Every field the schema knows is written back as
// the engine itself would write it.
//
// A node already holding more than one key (a rotation in progress) is refused even with
// `replace`: its extra keys are removed one by one with `remove_node_consensus_key` first.
NodeBindingOutcome bind_node_consensus_key(const NodeConsensusBinding& binding, NodeConsensusBindingResult& result,
                                           std::string& why);

// Several keys: a consensus key rotation without downtime.
//
// A validator rotating from key A to key B holds both for a while: A for the validator
// set that lists A until that set has ended, B for the stakes the controller (rebound to
// B) will accept. Which key signs what is decided by the windows below and by the sets
// themselves; see consensus-key-schedule.h.

// One key as a node configuration names it.
struct NodeConsensusKeyEntry {
  std::string key_file;
  std::uint32_t valid_from = 0;  // first election date it may sign a stake for
  std::uint32_t expire_at = 0;   // unix time from which it is not used; 0: never
  bool primary = false;          // the configuration's single `consensus_key_file`
};

struct NodeConsensusKeyAddition {
  std::string db_root;
  std::string key_file;  // absolute
  std::uint32_t valid_from = 0;
  std::uint32_t expire_at = 0;
  std::uint32_t now = 0;  // the time keys are judged expired at
};

// Add a key to a bound node's configuration, under the same lock and with the same
// refusals as `bind_node_consensus_key`. Refuses, writing nothing, when the node is not
// bound, when the key file fails the node's own seed checks, when the key would already
// have expired, when the file is already configured with another window, when the
// resulting set of keys is one the node would refuse at its next start (another key valid
// from the same election date, too many keys, a window that closes before it opens, the
// same key under two file names, a configured key that cannot be loaded). The same key
// with the same window already present is `unchanged`.
NodeBindingOutcome add_node_consensus_key(const NodeConsensusKeyAddition& addition, NodeConsensusBindingResult& result,
                                          std::string& why);

struct NodeConsensusKeyRemoval {
  std::string db_root;
  std::string key;  // the absolute key file path it is configured at, or its 64-hex key id
  std::uint32_t now = 0;  // the time the remaining keys are judged expired at
};

// Remove one key from a bound node's configuration. Refuses the node's last key, and a
// removal that would leave only expired keys or an otherwise invalid schedule. This
// sees no validator set: removing a key a running set still lists for this validator
// takes the validator out of that set's consensus until the set ends. The operator checks
// that first (or uses the console's del-pq-consensus-key on the running node, which does).
NodeBindingOutcome remove_node_consensus_key(const NodeConsensusKeyRemoval& removal, NodeConsensusBindingResult& result,
                                             std::string& why);

struct NodeConsensusKeyListing {
  struct Key {
    NodeConsensusKeyEntry entry;
    bool expired = false;
    bool loaded = false;  // whether the seed passes the node's checks
    std::array<std::uint8_t, 32> key_id{};
    std::string refusal;  // why it does not, when it does not
  };
  std::array<std::uint8_t, 32> validator_id{};
  std::vector<Key> keys;
};

// The keys a node's configuration names, each with the identity its seed derives (when
// it can be read under the node's rules). Read only, and without the lock.
bool list_node_consensus_keys(const std::string& db_root, std::uint32_t now, NodeConsensusKeyListing& listing,
                              std::string& why);

}  // namespace tos::pq
