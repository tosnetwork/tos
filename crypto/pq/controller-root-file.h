/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// A validator controller's root key, on disk, in the offline operator domain.
//
// This file and the signer it builds are deliberately not part of anything a validator
// host links. The boundary the offline-root split created is between two machines, not
// functions: a validator holds the key it can rotate, and the authority that rotates it
// lives where an operator keeps it. A node that could load this would be a node whose
// compromise costs the authority rather than the key, so the separation is a link-time
// one -- `tos_pq_controller_root` is not among validator-engine's libraries, and a gate
// fails if it becomes one.
//
// The local protections are exactly the ones the consensus key is read under, shared
// rather than restated. The refusals are named for this key because the words an
// operator reads should be about the key they are fixing.

#include <string_view>
#include <variant>

#include "controller-root-signer.h"

namespace tos::pq {

enum class ControllerRootFileError {
  cannot_open,         // absent, unreadable, or a symlink
  not_a_regular_file,  // a directory, a device, a socket
  wrong_owner,         // owned by somebody other than this process
  readable_by_others,  // any group or world bit set
  directory_writable,  // the directory holding it can be written by group or world
  wrong_size,          // a root seed is exactly 32 bytes
  read_failed,         // short read, or an error part way through
  derivation_failed,   // the backend refused the seed
};

// What went wrong, in the words an operator needs to fix it.
const char* describe(ControllerRootFileError error) noexcept;

// Load the root seed at `path` and derive the offline signer it stands for.
std::variant<ValidatorControllerRootKeyStore, ControllerRootFileError> load_controller_root_key(
    std::string_view path) noexcept;

}  // namespace tos::pq
