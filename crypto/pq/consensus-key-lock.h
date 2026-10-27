/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// The validator engine's exclusive hold on a consensus key file.
//
// Two engines that load the same consensus key file sign as one validator, and nothing
// in either one's own database would stop them from signing two different votes for
// one slot. The configuration lock is per database root, so two engines on different
// roots that point at one key file both start. This lock closes that one case: an
// engine holds an exclusive flock(2) on every consensus key file it signs with, and a
// second engine that opens the same file refuses to load the key.
//
// What it covers, and only that: two processes on one kernel that open the same file
// (the same inode), whatever path, bind mount or hard link they reach it by. It does not
// cover a copy of the seed (another inode), another host, or a seed on a network or
// userspace filesystem; the last is refused outright rather than locked in a way that
// would look like exclusion and not be.
//
// The lock lives as long as any signer built from the file: the store handed out
// shares its lifetime with the lock, so a group still signing with a key keeps the file
// locked after the key was removed from custody. Within one process every load of the
// same file shares one lock, so loading a key again neither conflicts with this
// engine's own lock nor releases a lock another live signer depends on.
//
// Only the engine takes it. The operator tools that read a seed offline do not.

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <variant>

#include "consensus-pq-signer.h"

namespace tos::pq {

// Load the consensus key at `path` under the same rules as `load_consensus_key`, with the
// signing deadline `expire_at` (0: none), holding the file's exclusive lock for as long
// as the returned signer or any copy of it exists. Returns the reason in an operator's
// words when the key is not loaded: the file is locked by another process, it is on a
// filesystem where the lock is not enforced, the key file itself is refused, or the file
// was replaced while it was being loaded.
std::variant<std::shared_ptr<const ValidatorPQKeyStore>, std::string> load_locked_consensus_key(
    std::string_view path, std::uint32_t expire_at);

// Whether a filesystem, by its statfs(2) f_type, is one the lock is enforced on: a local
// filesystem where every process that opens the file shares one kernel lock table.
bool consensus_key_lock_supported_filesystem(std::uint64_t f_type) noexcept;

}  // namespace tos::pq
