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
NodeBindingOutcome bind_node_consensus_key(const NodeConsensusBinding& binding, NodeConsensusBindingResult& result,
                                           std::string& why);

}  // namespace tos::pq
