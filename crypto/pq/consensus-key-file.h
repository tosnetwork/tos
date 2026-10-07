/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// The validator node's own post-quantum consensus key, on disk.
//
// A validator host holds one kind of post-quantum secret: the hot consensus key it signs
// finality, configuration votes and complaint votes with (two of them for a while during a
// key rotation; see consensus-key-schedule.h). The controller root, which
// authorises the stake and its own replacement, never reaches this machine, so a
// compromised validator costs an operator the key it can rotate and not the authority
// that rotates it.
//
// The file is a dedicated 32-byte ML-DSA-44 seed, the format `tos-pq-key` writes, kept
// apart from the ADNL/Ed25519 keyring. It is never read through that keyring, and the node
// has no path that sends it anywhere: the expanded secret exists only in the signer this
// builds, and the seed buffer is wiped once it has. The one deliberate way a seed leaves
// a file is the operator's `tos-pq-consensus-key export`, for the offline ceremony that
// binds a key to its controller; it is a command an operator types, not a node surface.
//
// Every refusal below is a property of the local machine, not of the chain, so a node
// that hits one has been misconfigured and must not start. That is why they are told
// apart rather than reported as one failure.

#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "consensus-pq-signer.h"
#include "seed-file.h"

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

// A refusal of the shared seed-file rules, as this key's refusal. Anything that reads a
// consensus seed with `detail::read_protected_seed` reports through this, so an operator
// reads the same words whichever command refused the file.
ConsensusKeyFileError consensus_key_refusal(detail::SeedFileRefusal refusal) noexcept;

// An identity (a key_id, a validator id, a public key) as lowercase hexadecimal: the one
// form `tos-pq-consensus-key` prints and the node logs, so an operator can compare the
// two as strings.
std::string identity_hex(std::string_view bytes);

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
// The node has no operation the other way. Reading a seed back out is the operator
// tool's `export`, which exists only for the offline binding ceremony.
std::variant<ConsensusPQKey, ConsensusKeyFileError> import_consensus_key(std::string_view path,
                                                                         std::string_view seed) noexcept;

}  // namespace tos::pq
