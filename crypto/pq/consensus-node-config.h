/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// Pointing a stopped node at its consensus key.
//
// A validator's `<db>/config.json` names the validator it signs for and the file its
// consensus seed is in (`extraconfig.pq_consensus`). The engine writes that file itself
// and rewrites it whenever its configuration changes, so this edits it only while no node
// holds the database, and writes it the way the engine does: the same TL schema, the same
// JSON encoding, a temporary file flushed and renamed over the old one.
//
// This is operator tooling. The node reads the binding; it never links this.

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace tos::pq {

struct NodeConsensusBinding {
  std::string config_path;                      // <db>/config.json
  std::string key_file;                         // absolute path the node will load the seed from
  std::array<std::uint8_t, 32> validator_id{};  // the controller's account id
  bool replace = false;                         // allow replacing a different existing binding
};

struct NodeConsensusBindingResult {
  std::array<std::uint8_t, 32> key_id{};  // what the key file derives, never what was typed
  bool changed = false;                   // false: the same binding was already there
};

// Parse a validator id as an operator has it: 64 hexadecimal digits, or the controller's
// masterchain address `-1:` followed by them. Refuses any other workchain and the zero id,
// which the engine refuses at start.
bool parse_validator_id(std::string_view text, std::array<std::uint8_t, 32>& out, std::string& why);

// Bind `binding.key_file` and `binding.validator_id` into the node configuration at
// `binding.config_path`. The id is taken as given: `parse_validator_id` is what refuses a
// zero one. On refusal returns false and says why in `why`; the configuration is then
// untouched.
bool bind_node_consensus_key(const NodeConsensusBinding& binding, NodeConsensusBindingResult& result, std::string& why);

}  // namespace tos::pq
