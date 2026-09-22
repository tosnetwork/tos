/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// The validator node's own post-quantum consensus key, on disk.
//
// A validator host holds exactly one post-quantum secret: the hot consensus key it signs
// finality, configuration votes and complaint votes with. The controller root, which
// authorises the stake and its own replacement, never reaches this machine, so a
// compromised validator costs an operator the key it can rotate and not the authority
// that rotates it.
//
// The file is a dedicated 32-byte ML-DSA-44 seed, the format `tos-pq-key` writes, kept
// apart from the ADNL/Ed25519 keyring. It is never read through that keyring and never
// leaves this machine through an export path: the expanded secret exists only in the
// signer this builds, and the seed buffer is wiped once it has.
//
// Every refusal below is a property of the local machine, not of the chain, so a node
// that hits one has been misconfigured and must not start. That is why they are told
// apart rather than reported as one failure.

#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "consensus-pq-signer.h"

namespace tos::pq {

// The file's whole content. A key is a seed, not a container: there is no header to get
// wrong and no version to disagree about.
inline constexpr std::size_t consensus_seed_bytes = 32;

enum class ConsensusKeyFileError {
  cannot_open,         // absent, unreadable, or a symlink
  not_a_regular_file,  // a directory, a device, a socket
  wrong_owner,         // owned by somebody other than this process
  readable_by_others,  // any group or world bit set
  directory_writable,  // the directory holding it can be written by group or world
  wrong_size,          // a seed is exactly 32 bytes
  read_failed,         // short read, or an error part way through
  derivation_failed,   // the backend refused the seed
  already_exists,      // creating one would replace a key that is already there
  write_failed,        // creating one did not complete
};

// What went wrong, in the words an operator needs to fix it.
const char* describe(ConsensusKeyFileError error) noexcept;

// Load the seed at `path` and derive the signer it stands for.
//
// The file must be a regular file this process owns, with no group or world bits, in a
// directory no one else can write, and exactly 32 bytes long. A symlink is refused
// rather than followed: the path an operator configured is the file that is read.
std::variant<ValidatorPQKeyStore, ConsensusKeyFileError> load_consensus_key(std::string_view path) noexcept;

// Create a new seed at `path` from the system's secure random source, and return the
// public key it derives. The file is owner-only from the moment it exists, written
// through a temporary name and renamed, and both it and its directory are flushed before
// this returns, so a key that is reported as created is one a restart will find.
//
// Refuses to replace a key that is already there. Rotating one is removing the old file
// deliberately, not overwriting it by accident.
std::variant<ConsensusPQKey, ConsensusKeyFileError> create_consensus_key(std::string_view path) noexcept;

// Write a seed an operator already holds -- from a backup taken before the host was
// rebuilt -- to `path`, under exactly the rules a created one is written by, and return
// the public key it derives. Refuses anything that is not 32 bytes, and refuses to
// replace a key that is already there.
//
// There is no operation the other way. The seed can be put in; it cannot be read back
// out, by this or by any other path in the node.
std::variant<ConsensusPQKey, ConsensusKeyFileError> import_consensus_key(std::string_view path,
                                                                         std::string_view seed) noexcept;

}  // namespace tos::pq
